// ⚠️ ESTE ARCHIVO TODAVÍA NO ESTÁ CONECTADO A NADA. Es solo un
// "vocabulario" que definimos desde el principio del proyecto para
// describir en qué momento del proceso está una transferencia — pero
// ningún otro archivo lo usa todavía. main.rs actualmente lleva el
// control de "en qué fase vamos" a mano, con variables sueltas
// (self.receiver_status, self.ble_offer, etc.) en vez de usar este
// enum de forma centralizada.
//
// Esto quedará útil el día que se quiera refactorizar main.rs para
// que sea más explícito sobre "en qué paso del protocolo estamos" —
// por ahora es más una nota de diseño que código funcional.

/// Fases del protocolo AirCore (ver documento de diseño v0.1).
#[derive(Debug, Clone, PartialEq)]
pub enum SessionPhase {
    Idle,                  // Nada está pasando.
    Advertising,           // El Receptor se está anunciando por BLE.
    Offering {             // El Emisor mandó una oferta (nombre+tamaño del archivo).
        peer_name: String,
        file_name: String,
        file_size: u64,
    },
    AwaitingBleApproval,       // Esperando que el Receptor acepte/rechace por BLE.
    ExchangingCredentials,     // Mandando el SSID+contraseña del hotspot.
    JoiningHotspot,            // El Emisor se está uniendo a la red Wi-Fi temporal.
    EstablishingSecureChannel, // Hachiendo el handshake Noise (por BLE o por TCP).
    AwaitingTransferApproval { // Esperando que el Receptor confirme, mostrando el código.
        verification_code: String,
    },
    Transferring,          // El archivo se está mandando de verdad.
    Completed,             // Todo salió bien.
    Failed { reason: String }, // Algo salió mal, y aquí está el porqué.
}