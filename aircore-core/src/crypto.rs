use crate::transport::Transport;
use snow::params::NoiseParams;
use snow::{Builder, TransportState};
use std::io;

pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
pub const MAX_FRAME_LEN: u32 = 70_000; // un poco más que el máximo de mensaje Noise (65535)

pub struct SecureChannel<T: Transport> {
    transport: T,
    noise: TransportState,
    handshake_hash: Vec<u8>,
}

impl<T: Transport> SecureChannel<T> {
    pub fn verification_code(&self) -> String {
        let hash = &self.handshake_hash;
        let n = u32::from_be_bytes([0, hash[0], hash[1], hash[2]]) % 1_000_000;
        format!("{:06}", n)
    }

    pub fn send(&mut self, plaintext: &[u8]) -> io::Result<()> {
        let mut buf = vec![0u8; plaintext.len() + 32];
        let len = self.noise.write_message(plaintext, &mut buf).map_err(noise_err)?;
        self.transport.send_frame(&buf[..len])
    }

    pub fn recv(&mut self, max_len: u32) -> io::Result<Vec<u8>> {
        let frame = self.transport.recv_frame(max_len)?;
        let mut buf = vec![0u8; frame.len()];
        let len = self.noise.read_message(&frame, &mut buf).map_err(noise_err)?;
        buf.truncate(len);
        Ok(buf)
    }
}

fn noise_err(e: snow::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("Error de cifrado: {:?}", e))
}

pub fn perform_handshake_initiator<T: Transport>(mut transport: T) -> io::Result<SecureChannel<T>> {
    let params: NoiseParams = NOISE_PATTERN
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "parámetros Noise inválidos"))?;
    let keypair = Builder::new(params.clone()).generate_keypair().map_err(noise_err)?;
    let mut noise = Builder::new(params)
        .local_private_key(&keypair.private)
        .build_initiator()
        .map_err(noise_err)?;

    let mut buf = vec![0u8; 65535];

    let len = noise.write_message(&[], &mut buf).map_err(noise_err)?;
    transport.send_frame(&buf[..len])?;

    let msg = transport.recv_frame(MAX_FRAME_LEN)?;
    noise.read_message(&msg, &mut buf).map_err(noise_err)?;

    let len = noise.write_message(&[], &mut buf).map_err(noise_err)?;
    transport.send_frame(&buf[..len])?;

    let handshake_hash = noise.get_handshake_hash().to_vec();
    let transport_state = noise.into_transport_mode().map_err(noise_err)?;
    Ok(SecureChannel { transport, noise: transport_state, handshake_hash })
}

pub fn perform_handshake_responder<T: Transport>(mut transport: T) -> io::Result<SecureChannel<T>> {
    let params: NoiseParams = NOISE_PATTERN
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "parámetros Noise inválidos"))?;
    let keypair = Builder::new(params.clone()).generate_keypair().map_err(noise_err)?;
    let mut noise = Builder::new(params)
        .local_private_key(&keypair.private)
        .build_responder()
        .map_err(noise_err)?;

    let mut buf = vec![0u8; 65535];

    let msg = transport.recv_frame(MAX_FRAME_LEN)?;
    noise.read_message(&msg, &mut buf).map_err(noise_err)?;

    let len = noise.write_message(&[], &mut buf).map_err(noise_err)?;
    transport.send_frame(&buf[..len])?;

    let msg = transport.recv_frame(MAX_FRAME_LEN)?;
    noise.read_message(&msg, &mut buf).map_err(noise_err)?;

    let handshake_hash = noise.get_handshake_hash().to_vec();
    let transport_state = noise.into_transport_mode().map_err(noise_err)?;
    Ok(SecureChannel { transport, noise: transport_state, handshake_hash })
}