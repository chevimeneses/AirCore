use crate::crypto::{SecureChannel, MAX_FRAME_LEN};
use crate::transport::Transport;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read, Write};

pub const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024 * 1024; // 10 GB

pub fn sanitize_filename(name: &str) -> String {
    std::path::Path::new(name)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty() && n != "." && n != "..")
        .unwrap_or_else(|| "archivo_recibido".to_string())
}

pub fn encode_metadata(file_name: &str, file_size: u64) -> Vec<u8> {
    let name_bytes = file_name.as_bytes();
    let mut meta = Vec::with_capacity(4 + name_bytes.len() + 8);
    meta.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
    meta.extend_from_slice(name_bytes);
    meta.extend_from_slice(&file_size.to_be_bytes());
    meta
}

pub fn decode_metadata(meta: &[u8]) -> Option<(String, u64)> {
    if meta.len() < 12 {
        return None;
    }
    let name_len = u32::from_be_bytes([meta[0], meta[1], meta[2], meta[3]]) as usize;
    if meta.len() < 4 + name_len + 8 {
        return None;
    }
    let raw_name = String::from_utf8_lossy(&meta[4..4 + name_len]).into_owned();
    let size_bytes: [u8; 8] = meta[4 + name_len..4 + name_len + 8].try_into().ok()?;
    let file_size = u64::from_be_bytes(size_bytes);
    Some((sanitize_filename(&raw_name), file_size))
}

/// Envía un archivo completo por un canal ya cifrado, en trozos de 8 KB.
pub fn send_file<T: Transport>(channel: &mut SecureChannel<T>, file: &mut File) -> io::Result<()> {
    let mut buffer = [0u8; 8192];
    let mut hasher = Sha256::new();
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        channel.send(&buffer[..n])?;
        hasher.update(&buffer[..n]);
    }
    let hash = hasher.finalize();
    channel.send(&hash)?;
    Ok(())
}

/// Recibe un archivo completo, verificando el hash SHA-256 al final.
/// Devuelve Ok(true) si el hash coincide, Ok(false) si no.
pub fn recv_file<T: Transport>(
    channel: &mut SecureChannel<T>,
    file: &mut File,
    file_size: u64,
) -> io::Result<bool> {
    let mut remaining = file_size;
    let mut hasher = Sha256::new();

    while remaining > 0 {
        let chunk = channel.recv(MAX_FRAME_LEN)?;
        if chunk.is_empty() || chunk.len() as u64 > remaining {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "chunk inesperado"));
        }
        file.write_all(&chunk)?;
        hasher.update(&chunk);
        remaining -= chunk.len() as u64;
    }
    file.flush()?;

    let hash_msg = channel.recv(64)?;
    let computed = hasher.finalize();
    Ok(hash_msg.as_slice() == computed.as_slice())
}