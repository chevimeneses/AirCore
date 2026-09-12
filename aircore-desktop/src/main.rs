// Este es el archivo donde TODO se junta: la interfaz gráfica (egui),
// y las llamadas a todas las piezas de Bluetooth/hotspot/TCP que
// viven en los demás archivos. Es el más grande porque es el
// "director de orquesta" de todo el proyecto.

use aircore_core::crypto::{perform_handshake_initiator, perform_handshake_responder, SecureChannel, MAX_FRAME_LEN};
use aircore_core::discovery::HotspotManager;
use aircore_core::transfer::{decode_metadata, encode_metadata, recv_file, send_file, MAX_FILE_SIZE};
use eframe::egui; // La librería de interfaz gráfica que usamos.
use rfd::FileDialog; // Para abrir el diálogo "elegir archivo" del sistema operativo.
use std::fs::{self, File};
use std::io;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

// Estas líneas "activan" los otros archivos .rs de esta carpeta como
// módulos — pero SOLO si estamos compilando para Windows. En Linux o
// macOS, ni siquiera se intentarían compilar (evita errores, ya que
// esos archivos usan APIs que solo existen en Windows).
#[cfg(target_os = "windows")]
mod ble_windows;
#[cfg(target_os = "windows")]
mod hotspot_windows;
#[cfg(target_os = "windows")]
mod gatt_server_windows;
#[cfg(target_os = "windows")]
mod gatt_client_windows;
#[cfg(target_os = "windows")]
mod ble_transport_windows;

const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Manda un mensaje de broadcast ("¿hay algún receptor por aquí?") a
/// toda la red local, y espera hasta `timeout` a que alguien responda.
/// Se usa tanto para el botón manual "Buscar (UDP)" como, más
/// importante, DESPUÉS de unirse a un hotspot BLE — porque una vez
/// dentro de esa red temporal, necesitamos encontrar la IP exacta del
/// Host sin que nadie nos la haya dicho directamente.
fn discover_receiver_ip(timeout: Duration) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_broadcast(true).ok()?;
    socket.set_read_timeout(Some(timeout)).ok()?;
    socket.send_to(b"BUSCANDO_AIR_RECEIVER", "255.255.255.255:5001").ok()?;
    let mut buf = [0u8; 1024];
    let (amt, src) = socket.recv_from(&mut buf).ok()?;
    let resp = String::from_utf8_lossy(&buf[..amt]);
    if resp == "ESTOY_AQUI_AIR_RECEIVER" {
        Some(src.ip().to_string())
    } else {
        None
    }
}

/// ⚠️ VERSIÓN TEMPORAL, NO SEGURA — genera un SSID y una contraseña
/// para el hotspot, pero usando la hora actual + el ID del proceso
/// como semilla, lo cual es ADIVINABLE por alguien que sepa
/// aproximadamente cuándo se generó. Está en la lista de pendientes
/// cambiarlo por un generador criptográficamente seguro (OsRng) antes
/// de que esto sea algo que otras personas usen de verdad.
#[cfg(target_os = "windows")]
fn generate_hotspot_credentials() -> (String, String) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let seed = now.as_nanos() as u64 ^ (std::process::id() as u64).rotate_left(32);
    let ssid = format!("AirCore-{:06X}", (seed & 0xFFFFFF) as u32);
    let password = format!("{:016X}", seed);
    (ssid, password)
}

/// Esta función hace TODA la parte final de "Transfer" (mandar el
/// archivo de verdad por TCP+Noise) — y es compartida entre los DOS
/// caminos posibles para llegar hasta aquí: el flujo manual (usuario
/// escribió una IP a mano) y el flujo por Bluetooth (se descubrió la
/// IP después de unirse al hotspot). No importa cómo llegamos hasta
/// tener una IP — de aquí en adelante todo es idéntico.
fn run_tcp_transfer(ip: String, file_path: String, tx: Sender<AppEvent>, ctx: egui::Context) {
    let result = (|| -> io::Result<()> {
        let mut file = File::open(&file_path)?;
        let file_size = file.metadata()?.len();
        let addr = format!("{}:5000", ip);

        let _ = tx.send(AppEvent::SenderStatus(format!("Conectando a {}...", addr)));
        ctx.request_repaint(); // Le decimos a la interfaz "vuelve a dibujarte ahora", para que se vea el cambio de inmediato.

        let stream = TcpStream::connect(&addr)?;
        stream.set_read_timeout(Some(READ_TIMEOUT))?;
        stream.set_write_timeout(Some(READ_TIMEOUT))?;

        let _ = tx.send(AppEvent::SenderStatus("Estableciendo canal cifrado...".to_string()));
        ctx.request_repaint();

        let mut channel = perform_handshake_initiator(stream)?; // El handshake Noise sobre TCP — el más probado de todo el proyecto.
        let code = channel.verification_code();

        let _ = tx.send(AppEvent::SenderVerificationCode(code)); // Mostramos el código de 6 dígitos en pantalla.
        ctx.request_repaint();

        let _ = tx.send(AppEvent::SenderStatus("Esperando aprobación del receptor...".to_string()));
        ctx.request_repaint();

        let file_name_only = std::path::Path::new(&file_path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "archivo_recibido".to_string());

        channel.send(&encode_metadata(&file_name_only, file_size))?; // Manda la oferta (ya cifrada).

        let approval = channel.recv(64)?; // Espera la respuesta del receptor: ¿aceptó o rechazó?
        if approval.first() != Some(&1) {
            let _ = tx.send(AppEvent::SenderStatus("El receptor rechazó la transferencia.".to_string()));
            ctx.request_repaint();
            return Ok(());
        }

        let _ = tx.send(AppEvent::SenderStatus("¡Aceptado! Transmitiendo datos...".to_string()));
        ctx.request_repaint();

        send_file(&mut channel, &mut file)?; // Aquí es donde de verdad se manda el archivo, byte por byte.

        let _ = tx.send(AppEvent::SenderStatus("¡Transferencia completada con éxito!".to_string()));
        ctx.request_repaint();
        Ok(())
    })();

    if let Err(e) = result {
        let _ = tx.send(AppEvent::SenderStatus(format!("Error: {}", e)));
        ctx.request_repaint();
    }
}

// Un dispositivo BLE que encontramos al escanear — solo guarda datos.
#[derive(Clone)]
struct BleDevice {
    name: String,
    address: u64, // La dirección Bluetooth cruda, necesaria para poder conectarnos a él después.
}

// TODOS los "avisos" que pueden llegar desde los hilos de fondo hacia
// la interfaz gráfica. Como la GUI y los hilos de red corren al mismo
// tiempo pero por separado, esta es la única forma en que se
// "hablan" entre sí de forma segura.
enum AppEvent {
    // Llegó una conexión TCP+Noise completa (ya sea del flujo manual
    // o después de un hotspot BLE) — trae el canal cifrado listo para
    // usar.
    IncomingRequest {
        peer_ip: String,
        file_name: String,
        file_size: u64,
        verification_code: String,
        channel: SecureChannel<TcpStream>,
    },
    SenderStatus(String),           // Actualiza el texto de estado del lado Emisor.
    SenderVerificationCode(String), // El código de 6 dígitos a mostrar del lado Emisor.
    ReceiverStatus(String),         // Actualiza el texto de estado del lado Receptor.
    BleDeviceFound(BleDevice),      // El escáner BLE encontró un dispositivo nuevo.

    /// Llegó una oferta por BLE. `decision_tx` es cómo la GUI le avisa
    /// al hilo de fondo qué decidió el usuario: Some((ssid,password))
    /// si aceptó (y ya arrancó el hotspot), None si rechazó.
    BleOfferReceived {
        name: String,
        size: u64,
        decision_tx: Sender<Option<(String, String)>>,
    },
}

// Todo el "estado" de la aplicación — todo lo que puede cambiar
// mientras la app corre vive aquí adentro.
struct AirCoreApp {
    mode: AppMode,                    // ¿Estamos en modo Emisor o Receptor ahora mismo?
    selected_file: Option<String>,    // El archivo que el usuario eligió para enviar.
    target_ip: String,                // La IP escrita a mano (o encontrada automáticamente).
    sender_status: String,            // El texto de estado que se ve del lado Emisor.
    sender_verification_code: Option<String>,
    searching: bool,
    receiver_listening: bool,         // ¿Ya arrancamos los servidores del lado Receptor?
    incoming_request: Option<(String, String, u64, String, SecureChannel<TcpStream>)>, // Solicitud TCP pendiente de aceptar/rechazar.
    receiver_status: String,          // El texto de estado que se ve del lado Receptor.
    event_rx: Receiver<AppEvent>,     // Por aquí la GUI "escucha" los avisos de los hilos de fondo.
    event_tx: Sender<AppEvent>,       // Este se clona y se le da a cada hilo nuevo, para que puedan mandar avisos.

    discovered_ble_devices: Vec<BleDevice>,   // La lista de dispositivos BLE encontrados hasta ahora.
    selected_ble_device_index: Option<usize>, // Cuál de esa lista eligió el usuario (si eligió alguno).

    /// Oferta BLE pendiente de que el usuario acepte o rechace.
    ble_offer: Option<(String, u64, Sender<Option<(String, String)>>)>,
}

#[derive(PartialEq)]
enum AppMode {
    Sender,
    Receiver,
}

impl AirCoreApp {
    // Se ejecuta UNA sola vez, al abrir la app — arma el estado
    // inicial con valores por default (nada seleccionado, nada
    // corriendo todavía).
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark()); // Tema oscuro para la interfaz.
        let (event_tx, event_rx) = mpsc::channel();
        Self {
            mode: AppMode::Sender, // Al abrir la app, empieza en modo Emisor por default.
            selected_file: None,
            target_ip: String::new(),
            sender_status: "Listo para enviar".to_string(),
            sender_verification_code: None,
            searching: false,
            receiver_listening: false,
            incoming_request: None,
            receiver_status: "Apagado".to_string(),
            event_rx,
            event_tx,
            discovered_ble_devices: Vec::new(),
            selected_ble_device_index: None,
            ble_offer: None,
        }
    }

    /// Se llama UNA vez, la primera vez que el usuario entra a "Modo
    /// Receptor" — arranca TRES cosas en paralelo, cada una en su
    /// propio hilo, para que ninguna bloquee a las demás ni a la
    /// interfaz gráfica:
    /// 1. El servidor GATT de Bluetooth (nueva, capa BLE+hotspot).
    /// 2. El servidor UDP (para que otros nos puedan encontrar en red).
    /// 3. El servidor TCP (donde de verdad llega el archivo).
    fn start_receiver_server(&mut self) {
        if self.receiver_listening {
            return; // Si ya arrancamos antes, no lo hacemos de nuevo.
        }
        self.receiver_listening = true;
        self.receiver_status = "Iniciando servidor y BLE...".to_string();

        // ── Hilo 1: servidor GATT de Bluetooth ──
        // Solo existe en Windows. Esto reemplaza al viejo
        // WindowsBleAdvertiser: ahora el anuncio y la capacidad de
        // recibir conexiones vienen juntos en WindowsGattServer.
        #[cfg(target_os = "windows")]
        {
            let tx_ble = self.event_tx.clone();
            thread::spawn(move || {
                use crate::gatt_server_windows::WindowsGattServer;

                match WindowsGattServer::start() {
                    Ok((server, transport)) => {
                        let _ = tx_ble.send(AppEvent::ReceiverStatus(
                            "Escuchando (TCP 5000, UDP 5001) + BLE listo para una oferta...".to_string(),
                        ));

                        // accept_offer() se QUEDA ESPERANDO aquí hasta
                        // que alguien de verdad negocie por Bluetooth
                        // (handshake Noise + oferta). Este hilo no
                        // hace nada más mientras tanto.
                        match crate::gatt_server_windows::accept_offer(transport) {
                            Ok((mut channel, name, size)) => {
                                // Creamos un canal "de un solo uso" para
                                // que la GUI nos pueda avisar la decisión
                                // del usuario (aceptar/rechazar) de vuelta
                                // hacia este hilo de fondo.
                                let (decision_tx, decision_rx) =
                                    mpsc::channel::<Option<(String, String)>>();

                                let _ = tx_ble.send(AppEvent::BleOfferReceived {
                                    name,
                                    size,
                                    decision_tx,
                                });

                                // Se queda esperando aquí a que la GUI
                                // responda (el usuario le dio clic a
                                // "Aceptar" o "Rechazar" en la ventana
                                // emergente).
                                match decision_rx.recv() {
                                    Ok(Some((ssid, password))) => {
                                        // El usuario aceptó: el hotspot ya se
                                        // creó del lado de la GUI, aquí solo
                                        // mandamos sus credenciales por BLE.
                                        let _ = crate::gatt_server_windows::respond(
                                            &mut channel,
                                            crate::ble_transport_windows::HotspotResponse::Accepted {
                                                ssid,
                                                password,
                                            },
                                        );
                                    }
                                    _ => {
                                        // El usuario rechazó (o algo falló):
                                        // avisamos rechazo al Emisor.
                                        let _ = crate::gatt_server_windows::respond(
                                            &mut channel,
                                            crate::ble_transport_windows::HotspotResponse::Rejected,
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                let _ = tx_ble.send(AppEvent::ReceiverStatus(format!(
                                    "No se completó ninguna negociación Bluetooth: {}",
                                    e
                                )));
                            }
                        }

                        let _ = server.stop(); // Ya terminamos con esta negociación, apagamos el anuncio BLE.
                    }
                    Err(e) => {
                        let _ = tx_ble.send(AppEvent::ReceiverStatus(format!(
                            "Advertencia: no se pudo iniciar el servidor Bluetooth ({})",
                            e
                        )));
                    }
                }
            });
        }

        // ── Hilo 2: servidor UDP (descubrimiento en red) ──
        // Este es el mecanismo VIEJO y ya muy probado: cualquiera en
        // la misma red que mande "BUSCANDO_AIR_RECEIVER" recibe de
        // vuelta "ESTOY_AQUI_AIR_RECEIVER" — así es como se encuentran
        // dos dispositivos que YA comparten una red (sea la de tu
        // casa, o el hotspot recién creado por BLE).
        let tx = self.event_tx.clone();
        thread::spawn(move || {
            match UdpSocket::bind("0.0.0.0:5001") {
                Ok(udp_socket) => {
                    let _ = udp_socket.set_broadcast(true);
                    let mut buf = [0; 1024];
                    loop { // Este loop nunca termina — se queda escuchando para siempre mientras la app viva.
                        if let Ok((amt, src)) = udp_socket.recv_from(&mut buf) {
                            let msg = String::from_utf8_lossy(&buf[..amt]);
                            if msg == "BUSCANDO_AIR_RECEIVER" {
                                let _ = udp_socket.send_to(b"ESTOY_AQUI_AIR_RECEIVER", src);
                            }
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(AppEvent::ReceiverStatus(format!(
                        "Error: no se pudo abrir el puerto UDP 5001 ({}).",
                        e
                    )));
                }
            }
        });

        // ── Hilo 3: servidor TCP (donde de verdad llega el archivo) ──
        // Este es EL MÁS PROBADO de todo el proyecto — funciona
        // perfecto desde hace muchas sesiones de trabajo.
        let tx = self.event_tx.clone();
        thread::spawn(move || {
            match TcpListener::bind("0.0.0.0:5000") {
                Ok(listener) => {
                    let _ = tx.send(AppEvent::ReceiverStatus(
                        "Escuchando en puertos 5000 (TCP) y 5001 (UDP)...".to_string(),
                    ));
                    // Este loop se queda esperando conexiones nuevas
                    // para siempre, una por una.
                    for stream in listener.incoming() {
                        let Ok(stream) = stream else { continue }; // Si algo salió mal con esta conexión en particular, la ignoramos y seguimos esperando la siguiente.
                        let peer_ip = stream.peer_addr().map(|p| p.ip().to_string()).unwrap_or_default();

                        let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
                        let _ = stream.set_write_timeout(Some(READ_TIMEOUT));

                        // Intentamos el handshake Noise. Si falla (alguien
                        // mandó basura, o no habla nuestro protocolo),
                        // simplemente descartamos esta conexión y
                        // seguimos esperando la siguiente — sin tronar.
                        let mut channel = match perform_handshake_responder(stream) {
                            Ok(c) => c,
                            Err(_) => continue,
                        };

                        let meta = match channel.recv(MAX_FRAME_LEN) {
                            Ok(m) => m,
                            Err(_) => continue,
                        };

                        let Some((file_name, file_size)) = decode_metadata(&meta) else { continue };

                        // Si el archivo es más grande que nuestro
                        // límite, lo rechazamos automáticamente sin
                        // siquiera preguntarle al usuario.
                        if file_size > MAX_FILE_SIZE {
                            let _ = channel.send(&[0]);
                            continue;
                        }

                        let verification_code = channel.verification_code();

                        // Le avisamos a la GUI: "llegó una solicitud
                        // real, muéstrale la ventana emergente al
                        // usuario para que decida".
                        let _ = tx.send(AppEvent::IncomingRequest {
                            peer_ip,
                            file_name,
                            file_size,
                            verification_code,
                            channel,
                        });
                    }
                }
                Err(e) => {
                    let _ = tx.send(AppEvent::ReceiverStatus(format!(
                        "Error: no se pudo abrir el puerto TCP 5000 ({}).",
                        e
                    )));
                }
            }
        });
    }
}

// Esta es la función que egui llama automáticamente, muchas veces por
// segundo, para "redibujar" la interfaz — aquí vive TODA la lógica
// visual de la app.
impl eframe::App for AirCoreApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Primero: revisamos si llegó algún aviso nuevo de los hilos
        // de fondo desde la última vez que se dibujó la pantalla, y
        // actualizamos el estado de la app en consecuencia.
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                AppEvent::IncomingRequest { peer_ip, file_name, file_size, verification_code, channel } => {
                    self.incoming_request = Some((peer_ip, file_name, file_size, verification_code, channel));
                }
                AppEvent::SenderStatus(status) => {
                    if status.starts_with("IP_DETECTADA:") {
                        let ip = status.strip_prefix("IP_DETECTADA:").unwrap().to_string();
                        self.target_ip = ip.clone();
                        self.sender_status = format!("¡Encontrado en IP: {}!", ip);
                    } else {
                        self.sender_status = status;
                    }
                }
                AppEvent::SenderVerificationCode(code) => {
                    self.sender_verification_code = Some(code);
                }
                AppEvent::ReceiverStatus(status) => {
                    self.receiver_status = status;
                }
                AppEvent::BleDeviceFound(device) => {
                    // Evitamos agregar el mismo dispositivo dos veces
                    // a la lista, si ya lo habíamos visto antes.
                    if !self.discovered_ble_devices.iter().any(|d| d.address == device.address) {
                        self.discovered_ble_devices.push(device);
                    }
                }
                AppEvent::BleOfferReceived { name, size, decision_tx } => {
                    self.ble_offer = Some((name, size, decision_tx)); // Guarda la oferta para que se muestre la ventana emergente.
                }
            }
        }

        // ── Ventana emergente 1: solicitud vía TCP+Noise directo ──
        // Esto pasa cuando ya llegó una conexión TCP real y validada
        // (ya sea del flujo manual, o después de un hotspot BLE que
        // ya funcionó) — es el mismo comportamiento de siempre, sin
        // ningún cambio de esta sesión.
        let incoming_data = if self.mode == AppMode::Receiver {
            self.incoming_request.as_ref().map(|(ip, name, size, code, _)| {
                (ip.clone(), name.clone(), *size, code.clone())
            })
        } else {
            None
        };

        if let Some((peer_ip, file_name, file_size, code)) = incoming_data {
            egui::Window::new("🚨 Solicitud de Archivo Entrante")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.spacing_mut().item_spacing.y = 10.0;
                    ui.heading("¡Dispositivo cercano quiere enviarte algo!");
                    ui.separator();
                    ui.label(format!("💻 IP Emisor: {}", peer_ip));
                    ui.label(format!("📁 Archivo: '{}'", file_name));
                    ui.label(format!("📦 Tamaño: {} bytes", file_size));
                    ui.separator();
                    ui.colored_label(egui::Color32::YELLOW, format!("🔑 Código de verificación: {}", code));
                    ui.label("Confírmalo con la persona que envía antes de aceptar.");
                    ui.separator();

                    ui.horizontal(|ui| {
                        if ui.button("❌ Rechazar").clicked() {
                            if let Some((_, _, _, _, mut channel)) = self.incoming_request.take() {
                                let _ = channel.send(&[0]);
                            }
                            self.receiver_status = "Transferencia rechazada.".to_string();
                        }
                        if ui.button("✅ Aceptar y Guardar").clicked() {
                            let (_, _, file_size, _, mut channel) = self.incoming_request.take().unwrap();
                            let file_name_clone = file_name.clone();
                            let tx = self.event_tx.clone();
                            let ctx_clone = ctx.clone();

                            // La recepción del archivo pasa en un hilo
                            // aparte, para que la ventana de la app no
                            // se congele mientras dura la transferencia.
                            thread::spawn(move || {
                                let result = (|| -> io::Result<()> {
                                    channel.send(&[1])?; // Le avisamos al Emisor: "sí, acepto".

                                    let _ = fs::create_dir_all("descargas_air");
                                    let path = std::path::Path::new("descargas_air").join(&file_name_clone);
                                    let mut file = File::create(&path)?;

                                    let ok = recv_file(&mut channel, &mut file, file_size)?;

                                    if ok {
                                        let _ = tx.send(AppEvent::ReceiverStatus(format!(
                                            "¡Recibido y verificado: {}!",
                                            file_name_clone
                                        )));
                                    } else {
                                        let _ = tx.send(AppEvent::ReceiverStatus(
                                            "¡Error de integridad SHA-256!".to_string(),
                                        ));
                                    }
                                    Ok(())
                                })();

                                if let Err(e) = result {
                                    let _ = tx.send(AppEvent::ReceiverStatus(format!("Error en recepción: {}", e)));
                                }
                                ctx_clone.request_repaint();
                            });

                            self.receiver_status = "Recibiendo archivo en segundo plano...".to_string();
                        }
                    });
                });
        }

        // ── Ventana emergente 2 (NUEVA): solicitud vía Bluetooth ──
        // Esta aparece ANTES de que exista cualquier hotspot o
        // conexión TCP — es la primera confirmación del usuario,
        // basada únicamente en lo que llegó por BLE.
        if self.mode == AppMode::Receiver {
            let ble_data = self.ble_offer.as_ref().map(|(name, size, _)| (name.clone(), *size));

            if let Some((name, size)) = ble_data {
                egui::Window::new("🔵 Solicitud vía Bluetooth")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, -140.0]) // Un poco más arriba que la otra ventana, para que no se encimen si algún día coinciden.
                    .show(ctx, |ui| {
                        ui.heading("Un dispositivo cercano quiere enviarte un archivo");
                        ui.separator();
                        ui.label(format!("📁 Archivo: '{}'", name));
                        ui.label(format!("📦 Tamaño: {} bytes", size));
                        ui.label("Al aceptar, se creará una red Wi-Fi temporal para la transferencia.");
                        ui.separator();

                        ui.horizontal(|ui| {
                            if ui.button("❌ Rechazar").clicked() {
                                if let Some((_, _, decision_tx)) = self.ble_offer.take() {
                                    let _ = decision_tx.send(None); // Avisa al hilo de fondo: "no, rechacé".
                                }
                                self.receiver_status = "Solicitud Bluetooth rechazada.".to_string();
                            }
                            if ui.button("✅ Aceptar").clicked() {
                                if let Some((_, _, decision_tx)) = self.ble_offer.take() {
                                    let tx = self.event_tx.clone();
                                    let ctx_clone = ctx.clone();

                                    // ⚠️ NUNCA PROBADO EN VIVO: este bloque
                                    // completo (generar credenciales, crear
                                    // el hotspot, mandar la respuesta por
                                    // BLE) es justo lo que la prueba de las
                                    // dos laptops va a confirmar.
                                    #[cfg(target_os = "windows")]
                                    thread::spawn(move || {
                                        let (ssid, password) = generate_hotspot_credentials();
                                        let mut manager = crate::hotspot_windows::WindowsHotspotManager::new();

                                        match manager.start_hotspot(&ssid, &password) {
                                            Ok(_) => {
                                                // Avisamos al hilo de BLE (el
                                                // que está esperando en
                                                // decision_rx.recv()) que sí
                                                // aceptamos, mandándole las
                                                // credenciales para que las
                                                // reenvíe por Bluetooth.
                                                let _ = decision_tx.send(Some((ssid.clone(), password.clone())));
                                                let _ = tx.send(AppEvent::ReceiverStatus(format!(
                                                    "Hotspot '{}' activo. Esperando a que el emisor se conecte...",
                                                    ssid
                                                )));
                                                ctx_clone.request_repaint();

                                                // Red de seguridad: si nadie más lo detiene antes,
                                                // el hotspot se apaga solo tras 10 minutos.
                                                thread::sleep(Duration::from_secs(600));
                                                let _ = manager.stop_hotspot();
                                            }
                                            Err(e) => {
                                                let _ = decision_tx.send(None); // Si falló crear el hotspot, avisamos rechazo.
                                                let _ = tx.send(AppEvent::ReceiverStatus(format!(
                                                    "No se pudo crear el hotspot: {}",
                                                    e
                                                )));
                                                ctx_clone.request_repaint();
                                            }
                                        }
                                    });

                                    self.receiver_status = "Creando hotspot temporal...".to_string();
                                }
                            }
                        });
                    });
            }
        }

        // ── El resto de la interfaz: paneles principales ──
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("🚀 AirCore - Transferencia Local");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // Los dos botones de arriba a la derecha, para
                    // cambiar entre Modo Receptor y Modo Emisor.
                    if ui.selectable_label(self.mode == AppMode::Receiver, "📥 Modo Receptor").clicked() {
                        self.mode = AppMode::Receiver;
                        self.start_receiver_server(); // Solo hace algo la PRIMERA vez (por el "if self.receiver_listening" de arriba).
                    }
                    if ui.selectable_label(self.mode == AppMode::Sender, "📤 Modo Emisor").clicked() {
                        self.mode = AppMode::Sender;
                    }
                });
            });
            ui.separator();

            match self.mode {
                AppMode::Sender => {
                    ui.add_space(10.0);
                    ui.heading("Panel de Envío");
                    ui.separator();

                    // Botón para elegir el archivo a enviar, usando el
                    // diálogo nativo del sistema operativo.
                    ui.horizontal(|ui| {
                        if ui.button("📂 Seleccionar Archivo").clicked() {
                            if let Some(path) = FileDialog::new().pick_file() {
                                self.selected_file = Some(path.display().to_string());
                            }
                        }
                        if let Some(ref path) = self.selected_file {
                            ui.label(format!("Archivo: {}", path));
                        } else {
                            ui.label("Ningún archivo seleccionado.");
                        }
                    });

                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        // Botón "Buscar (UDP)": el mecanismo VIEJO, que
                        // solo encuentra receptores que ya están en la
                        // MISMA red que nosotros.
                        if ui.button("🔍 Buscar (UDP)").clicked() {
                            self.searching = true;
                            self.sender_status = "Buscando receptores por red...".to_string();
                            let tx = self.event_tx.clone();
                            let ctx_clone = ctx.clone();

                            thread::spawn(move || {
                                if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
                                    let _ = socket.set_broadcast(true);
                                    let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));
                                    if socket.send_to(b"BUSCANDO_AIR_RECEIVER", "255.255.255.255:5001").is_ok() {
                                        let mut buf = [0; 1024];
                                        if let Ok((amt, src)) = socket.recv_from(&mut buf) {
                                            let resp = String::from_utf8_lossy(&buf[..amt]);
                                            if resp == "ESTOY_AQUI_AIR_RECEIVER" {
                                                let ip = src.ip().to_string();
                                                let _ = tx.send(AppEvent::SenderStatus(format!("IP_DETECTADA:{}", ip)));
                                                ctx_clone.request_repaint();
                                                return;
                                            }
                                        }
                                    }
                                }
                                let _ = tx.send(AppEvent::SenderStatus("No se encontró ningún receptor por red.".to_string()));
                                ctx_clone.request_repaint();
                            });
                        }

                        // Botón "Buscar BLE": el mecanismo NUEVO, que
                        // encuentra receptores CERCANOS sin importar
                        // si comparten red o no.
                        #[cfg(target_os = "windows")]
                        {
                            if ui.button("📶 Buscar BLE").clicked() {
                                self.sender_status = "Escaneando dispositivos BLE cercanos...".to_string();
                                self.discovered_ble_devices.clear(); // Limpia resultados de un escaneo anterior.
                                self.selected_ble_device_index = None;

                                let tx = self.event_tx.clone();
                                let ctx_clone = ctx.clone();

                                thread::spawn(move || {
                                    use crate::ble_windows::WindowsBleScanner;
                                    let mut scanner = WindowsBleScanner::new();

                                    let tx_callback = tx.clone();
                                    let result = scanner.start_scanning(move |name, addr| {
                                        let _ = tx_callback.send(AppEvent::BleDeviceFound(BleDevice { name, address: addr }));
                                    });

                                    if result.is_ok() {
                                        thread::sleep(Duration::from_secs(4)); // Escanea durante 4 segundos.
                                        let _ = scanner.stop_scanning();
                                        let _ = tx.send(AppEvent::SenderStatus("Escaneo BLE finalizado.".to_string()));
                                    } else {
                                        let _ = tx.send(AppEvent::SenderStatus("Error al iniciar el escáner Bluetooth.".to_string()));
                                    }
                                    ctx_clone.request_repaint();
                                });
                            }
                        }
                    });

                    // El menú desplegable (combo box) con los
                    // dispositivos BLE encontrados, para que el usuario
                    // elija uno en vez de escribir una IP a mano.
                    #[cfg(target_os = "windows")]
                    {
                        ui.add_space(5.0);
                        ui.horizontal(|ui| {
                            ui.label("Receptores BLE:");

                            let current_text = match self.selected_ble_device_index {
                                Some(idx) => {
                                    if let Some(dev) = self.discovered_ble_devices.get(idx) {
                                        format!("{} ({:#014X})", dev.name, dev.address)
                                    } else {
                                        "Seleccionar dispositivo...".to_string()
                                    }
                                }
                                None => {
                                    if self.discovered_ble_devices.is_empty() {
                                        "Ninguno encontrado".to_string()
                                    } else {
                                        "Seleccionar dispositivo...".to_string()
                                    }
                                }
                            };

                            egui::ComboBox::from_id_salt("ble_devices_combo")
                                .selected_text(current_text)
                                .show_ui(ui, |ui| {
                                    for (i, dev) in self.discovered_ble_devices.iter().enumerate() {
                                        let label = format!("{} ({:#014X})", dev.name, dev.address);
                                        let _ = ui.selectable_value(&mut self.selected_ble_device_index, Some(i), label);
                                    }
                                });

                            // Botón para "deseleccionar" y volver al modo manual.
                            if self.selected_ble_device_index.is_some() && ui.button("✖ Usar IP manual").clicked() {
                                self.selected_ble_device_index = None;
                            }
                        });
                    }

                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        ui.label("IP del Receptor:");
                        ui.text_edit_singleline(&mut self.target_ip); // Campo de texto donde se puede escribir una IP a mano.
                    });

                    ui.add_space(15.0);
                    // ── EL BOTÓN MÁS IMPORTANTE: "Enviar Archivo" ──
                    // Aquí es donde se decide CUÁL de los dos caminos
                    // seguir: por Bluetooth (si hay un dispositivo BLE
                    // seleccionado) o de forma manual (IP escrita a
                    // mano o encontrada por UDP).
                    if ui.button("🚀 Enviar Archivo").clicked() {
                        if let Some(ref file_path) = self.selected_file {
                            #[cfg(target_os = "windows")]
                            let ble_selected = self.selected_ble_device_index.and_then(|idx| {
                                self.discovered_ble_devices.get(idx).cloned()
                            });
                            #[cfg(not(target_os = "windows"))]
                            let ble_selected: Option<BleDevice> = None; // En otros sistemas operativos, esta ruta nunca existe.

                            if let Some(device) = ble_selected {
                                // ── CAMINO NUEVO: Bluetooth → hotspot → TCP ──
                                // ⚠️ ESTE CAMINO COMPLETO NUNCA SE HA
                                // PROBADO DE PUNTA A PUNTA — es justo lo
                                // que la prueba con la segunda laptop va
                                // a confirmar si funciona.
                                self.sender_verification_code = None;
                                let path_clone = file_path.clone();
                                let tx = self.event_tx.clone();
                                let ctx_clone = ctx.clone();

                                #[cfg(target_os = "windows")]
                                thread::spawn(move || {
                                    let result = (|| -> io::Result<()> {
                                        let file_name_only = std::path::Path::new(&path_clone)
                                            .file_name()
                                            .map(|n| n.to_string_lossy().into_owned())
                                            .unwrap_or_else(|| "archivo_recibido".to_string());
                                        let file_size = std::fs::metadata(&path_clone)?.len();

                                        let _ = tx.send(AppEvent::SenderStatus(format!(
                                            "Conectando por Bluetooth a '{}'...",
                                            device.name
                                        )));
                                        ctx_clone.request_repaint();

                                        // Paso 1: conectarse por BLE al
                                        // dispositivo elegido.
                                        let (_client, transport) =
                                            crate::gatt_client_windows::WindowsGattClient::connect(device.address)?;

                                        let _ = tx.send(AppEvent::SenderStatus(
                                            "Negociando con el receptor por Bluetooth...".to_string(),
                                        ));
                                        ctx_clone.request_repaint();

                                        // Paso 2: handshake Noise + mandar
                                        // oferta + esperar respuesta, todo
                                        // por Bluetooth.
                                        let response = crate::gatt_client_windows::negotiate(
                                            transport,
                                            &file_name_only,
                                            file_size,
                                        )?;

                                        match response {
                                            crate::ble_transport_windows::HotspotResponse::Rejected => {
                                                let _ = tx.send(AppEvent::SenderStatus(
                                                    "El receptor rechazó la solicitud (Bluetooth).".to_string(),
                                                ));
                                                ctx_clone.request_repaint();
                                            }
                                            crate::ble_transport_windows::HotspotResponse::Accepted {
                                                ssid,
                                                password,
                                            } => {
                                                let _ = tx.send(AppEvent::SenderStatus(format!(
                                                    "Aceptado. Uniéndose a la red '{}'... (perderás tu conexión actual)",
                                                    ssid
                                                )));
                                                ctx_clone.request_repaint();

                                                // Paso 3: unirse al hotspot
                                                // con las credenciales que
                                                // acabamos de recibir.
                                                let mut manager =
                                                    crate::hotspot_windows::WindowsHotspotManager::new();
                                                manager.join_network(&ssid, &password)?;

                                                let _ = tx.send(AppEvent::SenderStatus(
                                                    "Conectado. Buscando al receptor en la red temporal...".to_string(),
                                                ));
                                                ctx_clone.request_repaint();

                                                // Paso 4: ya en la misma red
                                                // que el Host, lo buscamos
                                                // con el mismo mecanismo
                                                // UDP de siempre.
                                                let ip = discover_receiver_ip(Duration::from_secs(8)).ok_or_else(|| {
                                                    io::Error::new(
                                                        io::ErrorKind::NotFound,
                                                        "no se encontró al receptor en la red del hotspot",
                                                    )
                                                })?;

                                                // Paso 5: con la IP en mano,
                                                // usamos exactamente la
                                                // misma función de siempre
                                                // para mandar el archivo.
                                                run_tcp_transfer(ip, path_clone.clone(), tx.clone(), ctx_clone.clone());
                                            }
                                        }
                                        Ok(())
                                    })();

                                    if let Err(e) = result {
                                        let _ = tx.send(AppEvent::SenderStatus(format!("Error (Bluetooth): {}", e)));
                                        ctx_clone.request_repaint();
                                    }
                                });
                            } else if self.target_ip.is_empty() {
                                self.sender_status =
                                    "Ingresa una IP, búscala por red, o selecciona un dispositivo BLE.".to_string();
                            } else {
                                // ── CAMINO VIEJO: IP manual → TCP ──
                                // ✅ Este es el flujo probado desde hace
                                // muchas sesiones, sin ningún cambio.
                                self.sender_verification_code = None;
                                let path_clone = file_path.clone();
                                let ip_clone = self.target_ip.clone();
                                let tx = self.event_tx.clone();
                                let ctx_clone = ctx.clone();

                                thread::spawn(move || run_tcp_transfer(ip_clone, path_clone, tx, ctx_clone));
                            }
                        } else {
                            self.sender_status = "Selecciona un archivo primero.".to_string();
                        }
                    }

                    ui.add_space(20.0);
                    ui.separator();
                    if let Some(ref code) = self.sender_verification_code {
                        ui.colored_label(egui::Color32::YELLOW, format!("🔑 Código de verificación: {}", code));
                    }
                    ui.label(format!("Estado: {}", self.sender_status));
                }
                AppMode::Receiver => {
                    ui.add_space(10.0);
                    ui.heading("Panel de Recepción");
                    ui.separator();
                    ui.label(format!("Estado del Servidor: {}", self.receiver_status));
                    ui.add_space(10.0);
                    ui.label("ℹ️ Los archivos aceptados se guardarán automáticamente en la carpeta 'descargas_air'.");
                }
            }
        });

        // Le pide a egui que vuelva a llamar esta función en máximo
        // 150 milisegundos, aunque no haya pasado nada — así los
        // avisos que llegan desde los hilos de fondo (BLE, TCP, etc.)
        // se reflejan en pantalla rápido, sin que el usuario tenga
        // que mover el mouse para "despertar" la interfaz.
        ctx.request_repaint_after(Duration::from_millis(150));
    }
}

// El punto de entrada de todo el programa — lo primero que se ejecuta
// al abrir la app.
fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([500.0, 400.0]), // Tamaño inicial de la ventana.
        ..Default::default()
    };
    eframe::run_native(
        "AirCore - Interfaz Gráfica", // Título de la ventana.
        options,
        Box::new(|cc| Ok(Box::new(AirCoreApp::new(cc)))), // Crea la app y la deja correr.
    )
}