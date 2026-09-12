use std::io::{self, Read, Write};
use std::net::TcpStream;

// PIEZA CLAVE DE ARQUITECTURA: este trait es lo que permite que el
// mismo código de cifrado (Noise) funcione tanto sobre TCP como sobre
// BLE, sin tener que escribirlo dos veces. Un "trait" en Rust es como
// un contrato: dice "cualquier cosa que implemente Transport debe
// saber mandar bytes y recibir bytes", sin importar CÓMO lo haga por
// dentro (por cable de red, por Bluetooth, etc).
//
// Gracias a esto, crypto.rs nunca necesita saber si está hablando por
// TCP o por Bluetooth — solo le pide al Transport "manda esto" o
// "dame el siguiente mensaje", y cada implementación resuelve el
// "cómo" a su manera.
pub trait Transport: Send {
    // Manda un mensaje completo (ya armado) por el canal.
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()>;

    // Espera y devuelve el siguiente mensaje completo que llegue.
    // max_len es un límite de seguridad: si alguien intenta mandar un
    // mensaje absurdamente grande, se rechaza en vez de intentar
    // reservar memoria sin límite.
    fn recv_frame(&mut self, max_len: u32) -> io::Result<Vec<u8>>;
}

// Aquí implementamos el "contrato" de Transport específicamente para
// TcpStream (una conexión de red normal). BLE tiene su propia
// implementación en otro archivo (ble_transport_windows.rs), pero
// ninguna de las dos sabe que la otra existe — ni falta que hace.
//
// Formato de "framing" usado: cada mensaje se manda como
// [4 bytes diciendo cuántos bytes vienen][esos bytes].
// Esto es necesario porque TCP es solo un chorro continuo de bytes —
// sin este truco, no sabríamos dónde termina un mensaje y empieza el
// siguiente.
impl Transport for TcpStream {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        let len = data.len() as u32;
        self.write_all(&len.to_be_bytes())?; // Primero mandamos "cuántos bytes vienen".
        self.write_all(data)?;               // Luego mandamos los bytes de verdad.
        Ok(())
    }

    fn recv_frame(&mut self, max_len: u32) -> io::Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        self.read_exact(&mut len_buf)?; // Leemos esos 4 bytes de "cuántos vienen".
        let len = u32::from_be_bytes(len_buf);

        // Si alguien dice "te voy a mandar 4 mil millones de bytes",
        // lo rechazamos de una vez en vez de intentar reservar esa
        // memoria — es una protección básica contra abuso.
        if len > max_len {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "frame demasiado grande"));
        }

        let mut buf = vec![0u8; len as usize];
        self.read_exact(&mut buf)?; // Ahora sí leemos exactamente esa cantidad de bytes.
        Ok(buf)
    }
}