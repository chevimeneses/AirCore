use crate::crypto::{SecureChannel, MAX_FRAME_LEN};
use crate::transport::Transport;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read, Write};

// Límite de seguridad: rechazamos automáticamente cualquier oferta de
// archivo que diga pesar más de 10 GB, para evitar que alguien llene
// el disco de la otra persona a propósito.
pub const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024 * 1024; // 10 GB

// Toma el nombre de archivo que mandó la otra persona y lo "limpia"
// para que sea seguro guardarlo en disco. Esto es importante porque
// si confiáramos ciegamente en el nombre que alguien más nos manda,
// podrían mandarnos algo como "../../../datos_importantes.txt" para
// intentar sobrescribir archivos fuera de la carpeta de descargas —
// esto se llama un ataque de "path traversal", y esta función lo evita.
pub fn sanitize_filename(name: &str) -> String {
    std::path::Path::new(name)
        .file_name() // Se queda solo con el nombre del archivo, tira cualquier ruta de carpetas.
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty() && n != "." && n != "..") // Rechaza nombres vacíos o "trampas".
        .unwrap_or_else(|| "archivo_recibido".to_string()) // Si algo salió raro, usa este nombre genérico.
}

// Convierte "nombre del archivo" + "tamaño" en una sola tira de bytes
// que se puede mandar por la red. Formato:
// [4 bytes: cuántas letras tiene el nombre][el nombre][8 bytes: el tamaño]
pub fn encode_metadata(file_name: &str, file_size: u64) -> Vec<u8> {
    let name_bytes = file_name.as_bytes();
    let mut meta = Vec::with_capacity(4 + name_bytes.len() + 8);
    meta.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
    meta.extend_from_slice(name_bytes);
    meta.extend_from_slice(&file_size.to_be_bytes());
    meta
}

// El proceso inverso: recibe esa tira de bytes y la vuelve a separar
// en (nombre, tamaño). Si algo no cuadra (datos incompletos, corruptos,
// etc.) devuelve None en vez de tronar — así el que llama puede
// decidir "ignorar este mensaje raro" en vez de que la app se caiga.
pub fn decode_metadata(meta: &[u8]) -> Option<(String, u64)> {
    if meta.len() < 12 {
        return None; // Muy corto para siquiera tener los campos obligatorios.
    }
    let name_len = u32::from_be_bytes([meta[0], meta[1], meta[2], meta[3]]) as usize;
    if meta.len() < 4 + name_len + 8 {
        return None; // Dice que el nombre mide X, pero no hay suficientes bytes para eso.
    }
    let raw_name = String::from_utf8_lossy(&meta[4..4 + name_len]).into_owned();
    let size_bytes: [u8; 8] = meta[4 + name_len..4 + name_len + 8].try_into().ok()?;
    let file_size = u64::from_be_bytes(size_bytes);
    Some((sanitize_filename(&raw_name), file_size)) // Nota: aquí también se sanitiza el nombre.
}

/// Envía un archivo completo por un canal ya cifrado, en trozos de 8 KB.
// "T: Transport" significa que esta función funciona con CUALQUIER
// cosa que sepa mandar/recibir bytes según el contrato de transport.rs
// — hoy la usamos con TCP, y también funciona igual con BLE, sin
// cambiar ni una línea de esta función.
pub fn send_file<T: Transport>(channel: &mut SecureChannel<T>, file: &mut File) -> io::Result<()> {
    let mut buffer = [0u8; 8192]; // Leemos el archivo en pedacitos de 8 KB, no todo de golpe.
    let mut hasher = Sha256::new(); // Vamos calculando un "resumen digital" del archivo mientras lo mandamos.
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break; // Ya no hay más que leer, el archivo se acabó.
        }
        channel.send(&buffer[..n])?; // Manda este pedacito (ya cifrado por dentro de channel.send).
        hasher.update(&buffer[..n]); // Lo suma al cálculo del hash.
    }
    let hash = hasher.finalize();
    channel.send(&hash)?; // Al final, manda el hash completo, para que el receptor pueda comparar.
    Ok(())
}

/// Recibe un archivo completo, verificando el hash SHA-256 al final.
/// Devuelve Ok(true) si el hash coincide, Ok(false) si no.
pub fn recv_file<T: Transport>(
    channel: &mut SecureChannel<T>,
    file: &mut File,
    file_size: u64, // Cuánto se supone que debe pesar el archivo (nos lo dijeron antes en la oferta).
) -> io::Result<bool> {
    let mut remaining = file_size; // Vamos restando conforme llega cada pedacito.
    let mut hasher = Sha256::new();

    while remaining > 0 {
        let chunk = channel.recv(MAX_FRAME_LEN)?; // Espera el siguiente pedacito.
        if chunk.is_empty() || chunk.len() as u64 > remaining {
            // Si llega un pedacito vacío, o más grande de lo que faltaba,
            // algo está mal (bug o intento de manipular la transferencia)
            // — mejor cortar aquí que seguir a ciegas.
            return Err(io::Error::new(io::ErrorKind::InvalidData, "chunk inesperado"));
        }
        file.write_all(&chunk)?; // Lo escribe al archivo en disco.
        hasher.update(&chunk);   // Lo suma al cálculo del hash de este lado.
        remaining -= chunk.len() as u64;
    }
    file.flush()?; // Se asegura de que todo lo escrito ya quedó guardado de verdad en disco.

    let hash_msg = channel.recv(64)?; // Espera el hash que mandó el emisor al final.
    let computed = hasher.finalize(); // El hash que calculamos nosotros mismos, de lo que llegó.

    // Si los dos hash coinciden, el archivo llegó exactamente igual que
    // se mandó — ni un byte se corrompió ni se perdió en el camino.
    Ok(hash_msg.as_slice() == computed.as_slice())
}