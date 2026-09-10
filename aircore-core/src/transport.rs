use std::io::{self, Read, Write};
use std::net::TcpStream;

/// Abstracción de un canal de bytes ordenado y confiable.
/// TCP la implementa hoy; BLE la implementará más adelante,
/// sin que crypto.rs necesite saber la diferencia.
pub trait Transport: Send {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()>;
    fn recv_frame(&mut self, max_len: u32) -> io::Result<Vec<u8>>;
}

// Framing: [u32 longitud][bytes]
impl Transport for TcpStream {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        let len = data.len() as u32;
        self.write_all(&len.to_be_bytes())?;
        self.write_all(data)?;
        Ok(())
    }

    fn recv_frame(&mut self, max_len: u32) -> io::Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        self.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf);
        if len > max_len {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "frame demasiado grande"));
        }
        let mut buf = vec![0u8; len as usize];
        self.read_exact(&mut buf)?;
        Ok(buf)
    }
}