#![cfg(target_os = "windows")]

use aircore_core::transport::Transport;
use std::io;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;
use windows::Devices::Bluetooth::GenericAttributeProfile::{
    GattCharacteristic, GattLocalCharacteristic, GattWriteOption,
};
use windows::Storage::Streams::DataWriter;

// A diferencia de TCP (que puede mandar mensajes de casi cualquier
// tamaño de una sola vez), Bluetooth solo permite mandar pedacitos
// pequeños en cada operación. 100 bytes es un tamaño conservador que
// funciona incluso sin negociar nada especial de antemano con el otro
// dispositivo.
const CHUNK_SIZE: usize = 100;

// Si pasan 15 segundos sin recibir ningún dato por BLE, nos damos por
// vencidos en vez de esperar para siempre — evita que la app se quede
// "colgada" si algo falla del otro lado.
const RECV_TIMEOUT: Duration = Duration::from_secs(15);

fn win_err_ctx(e: windows::core::Error, context: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Other,
        format!("Error de Windows BLE-transport en [{}]: {:?}", context, e),
    )
}

// PROBLEMA A RESOLVER: como cada mensaje de Noise es más grande que
// los 100 bytes que cabe en una sola escritura BLE, hay que partirlo
// en pedazos para mandarlo, y luego VOLVER A UNIRLO del otro lado
// antes de dárselo a Noise. Esta struct es la encargada de "volver a
// unir" los pedacitos que van llegando, hasta tener el mensaje
// completo.
struct FrameReassembler {
    buffer: Vec<u8>, // Aquí se van acumulando los pedacitos que van llegando.
}

impl FrameReassembler {
    fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    // Se llama cada vez que llega un pedacito nuevo. Devuelve
    // Some(mensaje_completo) si con este pedacito ya se completó un
    // mensaje entero, o None si todavía falta más por llegar.
    fn push(&mut self, chunk: &[u8]) -> Option<Vec<u8>> {
        self.buffer.extend_from_slice(chunk);
        if self.buffer.len() >= 4 {
            // Los primeros 4 bytes siempre dicen "cuántos bytes mide
            // el mensaje completo" (mismo truco de framing que usa TCP).
            let len = u32::from_be_bytes(self.buffer[0..4].try_into().unwrap()) as usize;
            if self.buffer.len() >= 4 + len {
                // ¡Ya tenemos todo el mensaje! Lo sacamos del buffer
                // y dejamos ahí solo lo que sobre (el inicio del
                // siguiente mensaje, si es que ya empezó a llegar).
                let frame = self.buffer[4..4 + len].to_vec();
                self.buffer.drain(0..4 + len);
                return Some(frame);
            }
        }
        None // Todavía falta más.
    }
}

// Función auxiliar compartida: toma un mensaje completo, le pone el
// encabezado de "cuántos bytes mide" al principio, y lo va mandando
// en pedacitos de CHUNK_SIZE, usando la función write_chunk que le
// pasen (que es distinta según si es el lado Host o el lado Guest).
fn chunk_and_send<W>(data: &[u8], mut write_chunk: W) -> io::Result<()>
where
    W: FnMut(&[u8]) -> io::Result<()>,
{
    let len = data.len() as u32;
    let mut framed = Vec::with_capacity(4 + data.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(data);

    for chunk in framed.chunks(CHUNK_SIZE) {
        write_chunk(chunk)?;
    }
    Ok(())
}

/// ✅ Esta struct "cumple" el contrato Transport (el mismo que ya
/// implementa TcpStream) — pero por dentro usa Bluetooth en vez de
/// una conexión de red. Es la mitad "Host" (el que recibe el archivo):
/// manda datos usando notificaciones BLE, y recibe datos a través de
/// una cola (rx) que se llena desde otro lado del código
/// (gatt_server_windows.rs) cada vez que el otro dispositivo escribe
/// algo.
pub struct BleServerTransport {
    notify_char: GattLocalCharacteristic, // Por aquí mandamos datos (usando notificaciones).
    rx: Receiver<Vec<u8>>,                // Por aquí "escuchamos" los pedacitos que van llegando.
    reassembler: FrameReassembler,        // Va juntando los pedacitos hasta tener un mensaje completo.
}

impl BleServerTransport {
    // Devuelve el transporte, junto con el "extremo emisor" (tx) de la
    // cola — ese tx se lo queda gatt_server_windows.rs para poder
    // avisarle a este transporte "llegó un pedacito nuevo" cada vez
    // que Windows le entregue datos.
    pub fn new(notify_char: GattLocalCharacteristic) -> (Self, Sender<Vec<u8>>) {
        let (tx, rx) = mpsc::channel();
        (
            Self { notify_char, rx, reassembler: FrameReassembler::new() },
            tx,
        )
    }
}

impl Transport for BleServerTransport {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        chunk_and_send(data, |chunk| {
            let writer = DataWriter::new().map_err(|e| win_err_ctx(e, "DataWriter::new"))?;
            writer.WriteBytes(chunk).map_err(|e| win_err_ctx(e, "writer.WriteBytes"))?;
            let buffer = writer.DetachBuffer().map_err(|e| win_err_ctx(e, "DetachBuffer"))?;
            // NotifyValueAsync = "avísale al otro dispositivo conectado
            // que este valor cambió" — así es como Bluetooth manda
            // datos del Host hacia el Guest.
            self.notify_char
                .NotifyValueAsync(&buffer)
                .map_err(|e| win_err_ctx(e, "NotifyValueAsync"))?
                .get()
                .map_err(|e| win_err_ctx(e, "NotifyValueAsync.get()"))?;
            Ok(())
        })
    }

    fn recv_frame(&mut self, _max_len: u32) -> io::Result<Vec<u8>> {
        loop {
            // Espera hasta que llegue un pedacito nuevo por la cola
            // (o hasta que pasen 15 segundos sin nada, y nos rendimos).
            let chunk = self
                .rx
                .recv_timeout(RECV_TIMEOUT)
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "timeout esperando datos BLE"))?;
            // Se lo pasamos al reensamblador; si con esto ya se
            // completó un mensaje, lo devolvemos. Si no, seguimos el
            // loop esperando más pedacitos.
            if let Some(frame) = self.reassembler.push(&chunk) {
                return Ok(frame);
            }
        }
    }
}

/// La misma idea que BleServerTransport, pero para el lado Guest (el
/// que envía el archivo): manda datos ESCRIBIENDO en una
/// característica GATT (en vez de notificar), y recibe datos de una
/// cola que se llena cuando el Host le notifica algo (ver
/// gatt_client_windows.rs).
pub struct BleClientTransport {
    write_char: GattCharacteristic,
    rx: Receiver<Vec<u8>>,
    reassembler: FrameReassembler,
}

impl BleClientTransport {
    pub fn new(write_char: GattCharacteristic) -> (Self, Sender<Vec<u8>>) {
        let (tx, rx) = mpsc::channel();
        (
            Self { write_char, rx, reassembler: FrameReassembler::new() },
            tx,
        )
    }
}

impl Transport for BleClientTransport {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        chunk_and_send(data, |chunk| {
            let writer = DataWriter::new().map_err(|e| win_err_ctx(e, "DataWriter::new"))?;
            writer.WriteBytes(chunk).map_err(|e| win_err_ctx(e, "writer.WriteBytes"))?;
            let buffer = writer.DetachBuffer().map_err(|e| win_err_ctx(e, "DetachBuffer"))?;
            // WriteValueWithOptionAsync = "escribe este valor en la
            // característica del otro dispositivo" — así es como
            // Bluetooth manda datos del Guest hacia el Host.
            // "WriteWithResponse" significa que esperamos confirmación
            // de que sí llegó, no solo lo mandamos y esperamos lo mejor.
            self.write_char
                .WriteValueWithOptionAsync(&buffer, GattWriteOption::WriteWithResponse)
                .map_err(|e| win_err_ctx(e, "WriteValueWithOptionAsync"))?
                .get()
                .map_err(|e| win_err_ctx(e, "WriteValueWithOptionAsync.get()"))?;
            Ok(())
        })
    }

    fn recv_frame(&mut self, _max_len: u32) -> io::Result<Vec<u8>> {
        loop {
            let chunk = self
                .rx
                .recv_timeout(RECV_TIMEOUT)
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "timeout esperando datos BLE"))?;
            if let Some(frame) = self.reassembler.push(&chunk) {
                return Ok(frame);
            }
        }
    }
}

/// Esto representa la decisión final del Host: o aceptó (y aquí están
/// las credenciales del hotspot que acaba de crear), o rechazó.
/// Como esto viaja DENTRO del canal ya cifrado por Noise, no
/// necesitamos preocuparnos de que alguien lo intercepte o lo
/// modifique en el camino — eso ya lo garantiza Noise por nosotros.
#[derive(Debug, Clone)]
pub enum HotspotResponse {
    Accepted { ssid: String, password: String },
    Rejected,
}

// Convierte la respuesta en bytes para poder mandarla. Formato:
// - Si rechazó: un solo byte, 0.
// - Si aceptó: un byte 1, luego [largo][ssid], luego [largo][contraseña].
pub fn encode_response(response: &HotspotResponse) -> Vec<u8> {
    match response {
        HotspotResponse::Rejected => vec![0],
        HotspotResponse::Accepted { ssid, password } => {
            let mut out = vec![1];
            for field in [ssid.as_str(), password.as_str()] {
                let bytes = field.as_bytes();
                out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(bytes);
            }
            out
        }
    }
}

// El proceso inverso: recibe esos bytes y los convierte de vuelta en
// un HotspotResponse. Si algo no cuadra, devuelve None en vez de
// tronar.
pub fn decode_response(bytes: &[u8]) -> Option<HotspotResponse> {
    if bytes.is_empty() {
        return None;
    }
    if bytes[0] == 0 {
        return Some(HotspotResponse::Rejected);
    }
    let mut pos = 1usize;
    let mut fields = Vec::with_capacity(2);
    for _ in 0..2 { // Esperamos exactamente 2 campos: ssid y contraseña.
        if bytes.len() < pos + 4 {
            return None;
        }
        let len = u32::from_be_bytes(bytes[pos..pos + 4].try_into().ok()?) as usize;
        pos += 4;
        if bytes.len() < pos + len {
            return None;
        }
        fields.push(String::from_utf8_lossy(&bytes[pos..pos + len]).into_owned());
        pos += len;
    }
    Some(HotspotResponse::Accepted { ssid: fields[0].clone(), password: fields[1].clone() })
}