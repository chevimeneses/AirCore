use aircore_core::crypto::{perform_handshake_initiator, perform_handshake_responder, SecureChannel, MAX_FRAME_LEN};
use aircore_core::discovery::HotspotManager;
use aircore_core::transfer::{decode_metadata, encode_metadata, recv_file, send_file, MAX_FILE_SIZE};
use eframe::egui;
use rfd::FileDialog;
use std::fs::{self, File};
use std::io;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

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

/// Escaneo UDP bloqueante: reutilizado tanto por el botón manual como
/// por el flujo mediado por BLE, una vez que el Guest ya se unió al
/// hotspot y necesita encontrar la IP del Host en esa red nueva.
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

/// Genera SSID + contraseña para el hotspot temporal. NOTA: no es un
/// generador criptográficamente seguro — placeholder consciente, ya
/// anotado en la lista de endurecimiento pendiente (usar OsRng).
#[cfg(target_os = "windows")]
fn generate_hotspot_credentials() -> (String, String) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let seed = now.as_nanos() as u64 ^ (std::process::id() as u64).rotate_left(32);
    let ssid = format!("AirCore-{:06X}", (seed & 0xFFFFFF) as u32);
    let password = format!("{:016X}", seed);
    (ssid, password)
}

/// Lógica de transferencia TCP+Noise, compartida entre el flujo manual
/// (IP escrita a mano) y el flujo mediado por BLE (IP descubierta tras
/// unirse al hotspot) — es la capa "Transfer" de la arquitectura,
/// reutilizada sin importar cómo se llegó a la conexión.
fn run_tcp_transfer(ip: String, file_path: String, tx: Sender<AppEvent>, ctx: egui::Context) {
    let result = (|| -> io::Result<()> {
        let mut file = File::open(&file_path)?;
        let file_size = file.metadata()?.len();
        let addr = format!("{}:5000", ip);

        let _ = tx.send(AppEvent::SenderStatus(format!("Conectando a {}...", addr)));
        ctx.request_repaint();

        let stream = TcpStream::connect(&addr)?;
        stream.set_read_timeout(Some(READ_TIMEOUT))?;
        stream.set_write_timeout(Some(READ_TIMEOUT))?;

        let _ = tx.send(AppEvent::SenderStatus("Estableciendo canal cifrado...".to_string()));
        ctx.request_repaint();

        let mut channel = perform_handshake_initiator(stream)?;
        let code = channel.verification_code();

        let _ = tx.send(AppEvent::SenderVerificationCode(code));
        ctx.request_repaint();

        let _ = tx.send(AppEvent::SenderStatus("Esperando aprobación del receptor...".to_string()));
        ctx.request_repaint();

        let file_name_only = std::path::Path::new(&file_path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "archivo_recibido".to_string());

        channel.send(&encode_metadata(&file_name_only, file_size))?;

        let approval = channel.recv(64)?;
        if approval.first() != Some(&1) {
            let _ = tx.send(AppEvent::SenderStatus("El receptor rechazó la transferencia.".to_string()));
            ctx.request_repaint();
            return Ok(());
        }

        let _ = tx.send(AppEvent::SenderStatus("¡Aceptado! Transmitiendo datos...".to_string()));
        ctx.request_repaint();

        send_file(&mut channel, &mut file)?;

        let _ = tx.send(AppEvent::SenderStatus("¡Transferencia completada con éxito!".to_string()));
        ctx.request_repaint();
        Ok(())
    })();

    if let Err(e) = result {
        let _ = tx.send(AppEvent::SenderStatus(format!("Error: {}", e)));
        ctx.request_repaint();
    }
}

#[derive(Clone)]
struct BleDevice {
    name: String,
    address: u64,
}

enum AppEvent {
    IncomingRequest {
        peer_ip: String,
        file_name: String,
        file_size: u64,
        verification_code: String,
        channel: SecureChannel<TcpStream>,
    },
    SenderStatus(String),
    SenderVerificationCode(String),
    ReceiverStatus(String),
    BleDeviceFound(BleDevice),
    /// Llegó una oferta por BLE. `decision_tx` es cómo la GUI le avisa
    /// al hilo de fondo qué decidió el usuario: Some((ssid,password))
    /// si aceptó (y ya arrancó el hotspot), None si rechazó.
    BleOfferReceived {
        name: String,
        size: u64,
        decision_tx: Sender<Option<(String, String)>>,
    },
}

struct AirCoreApp {
    mode: AppMode,
    selected_file: Option<String>,
    target_ip: String,
    sender_status: String,
    sender_verification_code: Option<String>,
    searching: bool,
    receiver_listening: bool,
    incoming_request: Option<(String, String, u64, String, SecureChannel<TcpStream>)>,
    receiver_status: String,
    event_rx: Receiver<AppEvent>,
    event_tx: Sender<AppEvent>,

    discovered_ble_devices: Vec<BleDevice>,
    selected_ble_device_index: Option<usize>,

    /// Oferta BLE pendiente de que el usuario acepte o rechace.
    ble_offer: Option<(String, u64, Sender<Option<(String, String)>>)>,
}

#[derive(PartialEq)]
enum AppMode {
    Sender,
    Receiver,
}

impl AirCoreApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        let (event_tx, event_rx) = mpsc::channel();
        Self {
            mode: AppMode::Sender,
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

    fn start_receiver_server(&mut self) {
        if self.receiver_listening {
            return;
        }
        self.receiver_listening = true;
        self.receiver_status = "Iniciando servidor y BLE...".to_string();

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

                        match crate::gatt_server_windows::accept_offer(transport) {
                            Ok((mut channel, name, size)) => {
                                let (decision_tx, decision_rx) =
                                    mpsc::channel::<Option<(String, String)>>();

                                let _ = tx_ble.send(AppEvent::BleOfferReceived {
                                    name,
                                    size,
                                    decision_tx,
                                });

                                match decision_rx.recv() {
                                    Ok(Some((ssid, password))) => {
                                        let _ = crate::gatt_server_windows::respond(
                                            &mut channel,
                                            crate::ble_transport_windows::HotspotResponse::Accepted {
                                                ssid,
                                                password,
                                            },
                                        );
                                    }
                                    _ => {
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

                        let _ = server.stop();
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

        let tx = self.event_tx.clone();
        thread::spawn(move || {
            match UdpSocket::bind("0.0.0.0:5001") {
                Ok(udp_socket) => {
                    let _ = udp_socket.set_broadcast(true);
                    let mut buf = [0; 1024];
                    loop {
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

        let tx = self.event_tx.clone();
        thread::spawn(move || {
            match TcpListener::bind("0.0.0.0:5000") {
                Ok(listener) => {
                    let _ = tx.send(AppEvent::ReceiverStatus(
                        "Escuchando en puertos 5000 (TCP) y 5001 (UDP)...".to_string(),
                    ));
                    for stream in listener.incoming() {
                        let Ok(stream) = stream else { continue };
                        let peer_ip = stream.peer_addr().map(|p| p.ip().to_string()).unwrap_or_default();

                        let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
                        let _ = stream.set_write_timeout(Some(READ_TIMEOUT));

                        let mut channel = match perform_handshake_responder(stream) {
                            Ok(c) => c,
                            Err(_) => continue,
                        };

                        let meta = match channel.recv(MAX_FRAME_LEN) {
                            Ok(m) => m,
                            Err(_) => continue,
                        };

                        let Some((file_name, file_size)) = decode_metadata(&meta) else { continue };

                        if file_size > MAX_FILE_SIZE {
                            let _ = channel.send(&[0]);
                            continue;
                        }

                        let verification_code = channel.verification_code();

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

impl eframe::App for AirCoreApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
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
                    if !self.discovered_ble_devices.iter().any(|d| d.address == device.address) {
                        self.discovered_ble_devices.push(device);
                    }
                }
                AppEvent::BleOfferReceived { name, size, decision_tx } => {
                    self.ble_offer = Some((name, size, decision_tx));
                }
            }
        }

        // Ventana de solicitud vía TCP+Noise directo (flujo manual o
        // ya conectado tras un hotspot BLE) — sin cambios de comportamiento.
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

                            thread::spawn(move || {
                                let result = (|| -> io::Result<()> {
                                    channel.send(&[1])?;

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

        // Ventana nueva: solicitud llegada por Bluetooth (Fase 2 del
        // protocolo) — antes de que exista ningún hotspot o conexión TCP.
        if self.mode == AppMode::Receiver {
            let ble_data = self.ble_offer.as_ref().map(|(name, size, _)| (name.clone(), *size));

            if let Some((name, size)) = ble_data {
                egui::Window::new("🔵 Solicitud vía Bluetooth")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, -140.0])
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
                                    let _ = decision_tx.send(None);
                                }
                                self.receiver_status = "Solicitud Bluetooth rechazada.".to_string();
                            }
                            if ui.button("✅ Aceptar").clicked() {
                                if let Some((_, _, decision_tx)) = self.ble_offer.take() {
                                    let tx = self.event_tx.clone();
                                    let ctx_clone = ctx.clone();

                                    #[cfg(target_os = "windows")]
                                    thread::spawn(move || {
                                        let (ssid, password) = generate_hotspot_credentials();
                                        let mut manager = crate::hotspot_windows::WindowsHotspotManager::new();

                                        match manager.start_hotspot(&ssid, &password) {
                                            Ok(_) => {
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
                                                let _ = decision_tx.send(None);
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

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("🚀 AirCore - Transferencia Local");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.selectable_label(self.mode == AppMode::Receiver, "📥 Modo Receptor").clicked() {
                        self.mode = AppMode::Receiver;
                        self.start_receiver_server();
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

                        #[cfg(target_os = "windows")]
                        {
                            if ui.button("📶 Buscar BLE").clicked() {
                                self.sender_status = "Escaneando dispositivos BLE cercanos...".to_string();
                                self.discovered_ble_devices.clear();
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
                                        thread::sleep(Duration::from_secs(4));
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

                            if self.selected_ble_device_index.is_some() && ui.button("✖ Usar IP manual").clicked() {
                                self.selected_ble_device_index = None;
                            }
                        });
                    }

                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        ui.label("IP del Receptor:");
                        ui.text_edit_singleline(&mut self.target_ip);
                    });

                    ui.add_space(15.0);
                    if ui.button("🚀 Enviar Archivo").clicked() {
                        if let Some(ref file_path) = self.selected_file {
                            #[cfg(target_os = "windows")]
                            let ble_selected = self.selected_ble_device_index.and_then(|idx| {
                                self.discovered_ble_devices.get(idx).cloned()
                            });
                            #[cfg(not(target_os = "windows"))]
                            let ble_selected: Option<BleDevice> = None;

                            if let Some(device) = ble_selected {
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

                                        let (_client, transport) =
                                            crate::gatt_client_windows::WindowsGattClient::connect(device.address)?;

                                        let _ = tx.send(AppEvent::SenderStatus(
                                            "Negociando con el receptor por Bluetooth...".to_string(),
                                        ));
                                        ctx_clone.request_repaint();

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

                                                let mut manager =
                                                    crate::hotspot_windows::WindowsHotspotManager::new();
                                                manager.join_network(&ssid, &password)?;

                                                let _ = tx.send(AppEvent::SenderStatus(
                                                    "Conectado. Buscando al receptor en la red temporal...".to_string(),
                                                ));
                                                ctx_clone.request_repaint();

                                                let ip = discover_receiver_ip(Duration::from_secs(8)).ok_or_else(|| {
                                                    io::Error::new(
                                                        io::ErrorKind::NotFound,
                                                        "no se encontró al receptor en la red del hotspot",
                                                    )
                                                })?;

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

        ctx.request_repaint_after(Duration::from_millis(150));
    }
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([500.0, 400.0]),
        ..Default::default()
    };
    eframe::run_native(
        "AirCore - Interfaz Gráfica",
        options,
        Box::new(|cc| Ok(Box::new(AirCoreApp::new(cc)))),
    )
}