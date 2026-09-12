// Este archivo es la "puerta de entrada" de la librería aircore-core.
// No contiene lógica propia — solo le dice a Rust qué otros archivos
// (módulos) existen dentro de esta librería, y cuáles de sus piezas
// quedan disponibles directamente como `aircore_core::algo` en vez de
// tener que escribir la ruta completa `aircore_core::crypto::algo`.

// Cada línea de abajo "activa" un archivo .rs del mismo nombre en esta
// carpeta (crypto.rs, discovery.rs, etc.) como parte de la librería.
pub mod crypto;      // Cifrado: el protocolo Noise y el canal seguro.
pub mod discovery;   // Los "contratos" (traits) de BLE y hotspot, sin implementación real todavía.
pub mod session;     // El vocabulario de fases del protocolo (aún no conectado a nada).
pub mod transfer;    // Envío/recepción de archivos: chunking, hash, sanitización de nombres.
pub mod transport;   // La abstracción que permite que Noise funcione igual sobre TCP o sobre BLE.

// Atajos: gracias a estas líneas, en vez de escribir
// aircore_core::crypto::SecureChannel en otro archivo, basta con
// escribir aircore_core::SecureChannel. Es solo comodidad, no cambia
// el comportamiento de nada.
pub use crypto::{perform_handshake_initiator, perform_handshake_responder, SecureChannel};
pub use transport::Transport;