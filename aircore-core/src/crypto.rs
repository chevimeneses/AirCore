use crate::transport::Transport;
use snow::params::NoiseParams;
use snow::{Builder, TransportState};
use std::io;

// "Noise_XX" es el nombre de un patrón de cifrado ya diseñado por
// expertos en criptografía (lo usan también apps como WhatsApp y
// WireGuard, aunque cada una con sus propios detalles). "XX" significa
// que ninguno de los dos lados necesita conocer de antemano la
// identidad del otro — se la intercambian y verifican durante el
// mismo proceso de conexión. 25519/ChaChaPoly/BLAKE2s son los
// algoritmos matemáticos específicos que usa por dentro.
pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

// Límite de tamaño para un solo mensaje cifrado — un poco más grande
// que el máximo que Noise permite mandar de una sola vez (65535
// bytes), para dejar margen sin ser un límite absurdo.
pub const MAX_FRAME_LEN: u32 = 70_000;

/// Esta struct ES el "canal seguro" — una vez que existe, todo lo que
/// mandes o recibas por ella queda automáticamente cifrado y
/// verificado, sin que el resto del código tenga que preocuparse por
/// los detalles de cómo funciona el cifrado por dentro.
///
/// El "T: Transport" es la magia que permite que esto funcione tanto
/// sobre TCP como sobre BLE — T es "lo que sea que sepa mandar/recibir
/// bytes según el contrato de transport.rs".
pub struct SecureChannel<T: Transport> {
    transport: T,               // El medio real (TCP o BLE) por donde viajan los bytes.
    noise: TransportState,      // El estado interno de cifrado de la librería snow.
    handshake_hash: Vec<u8>,    // Una "huella digital" única de esta conexión en particular.
}

impl<T: Transport> SecureChannel<T> {
    // Convierte la huella digital del handshake en un número de 6
    // dígitos fácil de leer en voz alta y comparar entre dos personas
    // — si alguien intentara interceptar la conexión (ataque
    // "man-in-the-middle"), el código que vería esa persona sería
    // DIFERENTE al que ven las dos partes legítimas, delatando el
    // ataque.
    pub fn verification_code(&self) -> String {
        let hash = &self.handshake_hash;
        let n = u32::from_be_bytes([0, hash[0], hash[1], hash[2]]) % 1_000_000;
        format!("{:06}", n) // Siempre 6 dígitos, con ceros a la izquierda si hace falta (ej: "004821").
    }

    // Cifra "plaintext" (datos sin cifrar) y lo manda por el
    // transporte. Quien llama a esta función nunca ve los bytes
    // cifrados — solo le da el mensaje original y listo.
    pub fn send(&mut self, plaintext: &[u8]) -> io::Result<()> {
        let mut buf = vec![0u8; plaintext.len() + 32]; // +32 de margen para el "sello" de autenticación que agrega Noise.
        let len = self.noise.write_message(plaintext, &mut buf).map_err(noise_err)?;
        self.transport.send_frame(&buf[..len])
    }

    // El proceso inverso: recibe bytes cifrados del transporte, y
    // devuelve el mensaje ya descifrado y verificado. Si alguien
    // intentó modificar los datos en el camino, esto falla en vez de
    // devolver datos corruptos silenciosamente.
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

// El "handshake" es la conversación inicial de 3 pasos donde dos
// dispositivos se ponen de acuerdo en una clave secreta compartida,
// sin haberla dicho nunca directamente (así funciona la criptografía
// de curva elíptica) — al final de esto, ambos lados tienen la misma
// llave secreta sin que nadie más que estuviera escuchando pueda
// deducirla.
//
// Hay dos roles: el que "inicia" la conversación (initiator) y el que
// "responde" (responder) — deben ser complementarios: uno de cada uno
// por conexión. El emisor siempre es el initiator; el receptor,
// el responder.
pub fn perform_handshake_initiator<T: Transport>(mut transport: T) -> io::Result<SecureChannel<T>> {
    let params: NoiseParams = NOISE_PATTERN
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "parámetros Noise inválidos"))?;

    // Genera un par de llaves (pública/privada) NUEVO para esta
    // conexión específica — no se reutiliza entre conexiones distintas,
    // lo cual es bueno para la privacidad (nadie puede "reconocerte"
    // de una conexión a otra por tu llave).
    let keypair = Builder::new(params.clone()).generate_keypair().map_err(noise_err)?;
    let mut noise = Builder::new(params)
        .local_private_key(&keypair.private)
        .build_initiator()
        .map_err(noise_err)?;

    let mut buf = vec![0u8; 65535];

    // Paso 1 del handshake: el initiator manda el primer mensaje.
    let len = noise.write_message(&[], &mut buf).map_err(noise_err)?;
    transport.send_frame(&buf[..len])?;

    // Paso 2: espera la respuesta del otro lado.
    let msg = transport.recv_frame(MAX_FRAME_LEN)?;
    noise.read_message(&msg, &mut buf).map_err(noise_err)?;

    // Paso 3: manda la confirmación final.
    let len = noise.write_message(&[], &mut buf).map_err(noise_err)?;
    transport.send_frame(&buf[..len])?;

    // El handshake ya terminó — guardamos su "huella digital" (para el
    // código de verificación) ANTES de pasar a "modo transporte",
    // porque una vez que cambiamos de modo, esa huella deja de estar
    // disponible (esto costó un bug real durante el desarrollo).
    let handshake_hash = noise.get_handshake_hash().to_vec();
    let transport_state = noise.into_transport_mode().map_err(noise_err)?;
    Ok(SecureChannel { transport, noise: transport_state, handshake_hash })
}

// Lo mismo que la función de arriba, pero desde el lado que "responde"
// en vez del que "inicia" — los pasos son los mismos tres mensajes,
// solo que en el orden espejo (primero espera, luego manda, luego
// espera otra vez).
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

    let msg = transport.recv_frame(MAX_FRAME_LEN)?; // Espera el primer mensaje del initiator.
    noise.read_message(&msg, &mut buf).map_err(noise_err)?;

    let len = noise.write_message(&[], &mut buf).map_err(noise_err)?; // Manda su respuesta.
    transport.send_frame(&buf[..len])?;

    let msg = transport.recv_frame(MAX_FRAME_LEN)?; // Espera la confirmación final.
    noise.read_message(&msg, &mut buf).map_err(noise_err)?;

    let handshake_hash = noise.get_handshake_hash().to_vec();
    let transport_state = noise.into_transport_mode().map_err(noise_err)?;
    Ok(SecureChannel { transport, noise: transport_state, handshake_hash })
}