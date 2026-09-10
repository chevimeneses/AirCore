use aircore_core::crypto::{perform_handshake_initiator, perform_handshake_responder, SecureChannel, MAX_FRAME_LEN};
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

const READ_TIMEOUT: Duration = Duration::from_secs(30);

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
        }
    }

    fn start_receiver_server(&mut self) {
        if self.receiver_listening {
            return;
        }
        self.receiver_listening = true;
        self.receiver_status = "Iniciando servidor...".to_string();

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
            }
        }

        let incoming_data = self.incoming_request.as_ref().map(|(ip, name, size, code, _)| {
            (ip.clone(), name.clone(), *size, code.clone())
        });

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
                    if ui.button("🔍 Buscar Receptor en la Red (UDP)").clicked() {
                        self.searching = true;
                        self.sender_status = "Buscando receptores...".to_string();
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
                            let _ = tx.send(AppEvent::SenderStatus("No se encontró ningún receptor.".to_string()));
                            ctx_clone.request_repaint();
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
                            if self.target_ip.is_empty() {
                                self.sender_status = "Por favor ingresa o busca una IP válida.".to_string();
                            } else {
                                self.sender_verification_code = None;
                                let path_clone = file_path.clone();
                                let ip_clone = self.target_ip.clone();
                                let tx = self.event_tx.clone();
                                let ctx_clone = ctx.clone();

                                thread::spawn(move || {
                                    let result = (|| -> io::Result<()> {
                                        let mut file = File::open(&path_clone)?;
                                        let file_size = file.metadata()?.len();
                                        let addr = format!("{}:5000", ip_clone);

                                        let _ = tx.send(AppEvent::SenderStatus(format!("Conectando a {}...", addr)));
                                        ctx_clone.request_repaint();

                                        let stream = TcpStream::connect(&addr)?;
                                        stream.set_read_timeout(Some(READ_TIMEOUT))?;
                                        stream.set_write_timeout(Some(READ_TIMEOUT))?;

                                        let _ = tx.send(AppEvent::SenderStatus("Estableciendo canal cifrado...".to_string()));
                                        ctx_clone.request_repaint();

                                        let mut channel = perform_handshake_initiator(stream)?;
                                        let code = channel.verification_code();

                                        let _ = tx.send(AppEvent::SenderVerificationCode(code));
                                        ctx_clone.request_repaint();

                                        let _ = tx.send(AppEvent::SenderStatus("Esperando aprobación del receptor...".to_string()));
                                        ctx_clone.request_repaint();

                                        let file_name_only = std::path::Path::new(&path_clone)
                                            .file_name()
                                            .map(|n| n.to_string_lossy().into_owned())
                                            .unwrap_or_else(|| "archivo_recibido".to_string());

                                        channel.send(&encode_metadata(&file_name_only, file_size))?;

                                        let approval = channel.recv(64)?;
                                        if approval.first() != Some(&1) {
                                            let _ = tx.send(AppEvent::SenderStatus("El receptor rechazó la transferencia.".to_string()));
                                            ctx_clone.request_repaint();
                                            return Ok(());
                                        }

                                        let _ = tx.send(AppEvent::SenderStatus("¡Aceptado! Transmitiendo datos...".to_string()));
                                        ctx_clone.request_repaint();

                                        send_file(&mut channel, &mut file)?;

                                        let _ = tx.send(AppEvent::SenderStatus("¡Transferencia completada con éxito!".to_string()));
                                        ctx_clone.request_repaint();
                                        Ok(())
                                    })();

                                    if let Err(e) = result {
                                        let _ = tx.send(AppEvent::SenderStatus(format!("Error: {}", e)));
                                        ctx_clone.request_repaint();
                                    }
                                });
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