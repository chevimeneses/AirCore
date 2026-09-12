#![cfg(target_os = "windows")]

use aircore_core::transport::Transport;
use std::io;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;
use windows::Devices::Bluetooth::GenericAttributeProfile::{
    GattCharacteristic, GattLocalCharacteristic, GattWriteOption,
};
use windows::Storage::Streams::DataWriter;

/// Tamaño de cada escritura GATT individual. BLE limita cuánto se
/// puede mandar en una sola operación; 100 bytes es conservador y
/// funciona incluso sin negociar un MTU grande. Si en la práctica
/// alguna operación falla por tamaño, este es el primer valor a bajar.
const CHUNK_SIZE: usize = 100;

const RECV_TIMEOUT: Duration = Duration::from_secs(15);

fn win_err_ctx(e: windows::core::Error, context: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Other,
        format!("Error de Windows BLE-transport en [{}]: {:?}", context, e),
    )
}

/// Reensambla mensajes fragmentados: cada mensaje lógico se manda
/// como [u32 longitud][bytes], partido en chunks de CHUNK_SIZE. Esta
/// estructura acumula chunks hasta tener un mensaje completo.
struct FrameReassembler {
    buffer: Vec<u8>,
}

impl FrameReassembler {
    fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    fn push(&mut self, chunk: &[u8]) -> Option<Vec<u8>> {
        self.buffer.extend_from_slice(chunk);
        if self.buffer.len() >= 4 {
            let len = u32::from_be_bytes(self.buffer[0..4].try_into().unwrap()) as usize;
            if self.buffer.len() >= 4 + len {
                let frame = self.buffer[4..4 + len].to_vec();
                self.buffer.drain(0..4 + len);
                return Some(frame);
            }
        }
        None
    }
}

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

/// Transporte Noise sobre BLE para el lado Host (servidor GATT).
/// Manda por la característica de credenciales (Notify), recibe por
/// una cola alimentada desde el handler de escritura de la
/// característica de oferta (ver gatt_server_windows.rs).
pub struct BleServerTransport {
    notify_char: GattLocalCharacteristic,
    rx: Receiver<Vec<u8>>,
    reassembler: FrameReassembler,
}

impl BleServerTransport {
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

/// Transporte Noise sobre BLE para el lado Guest (cliente GATT).
/// Manda por la característica de oferta (Write), recibe por una
/// cola alimentada desde el handler ValueChanged de la característica
/// de credenciales (ver gatt_client_windows.rs).
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

/// Payload de la respuesta del Host, ya viajando DENTRO del canal
/// cifrado — a diferencia de antes, ya no necesita ir firmado aparte
/// porque Noise ya garantiza autenticidad e integridad.
#[derive(Debug, Clone)]
pub enum HotspotResponse {
    Accepted { ssid: String, password: String },
    Rejected,
}

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

pub fn decode_response(bytes: &[u8]) -> Option<HotspotResponse> {
    if bytes.is_empty() {
        return None;
    }
    if bytes[0] == 0 {
        return Some(HotspotResponse::Rejected);
    }
    let mut pos = 1usize;
    let mut fields = Vec::with_capacity(2);
    for _ in 0..2 {
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