/// Fases del protocolo AirCore (ver documento de diseño v0.1).
#[derive(Debug, Clone, PartialEq)]
pub enum SessionPhase {
    Idle,
    Advertising,
    Offering { peer_name: String, file_name: String, file_size: u64 },
    AwaitingBleApproval,
    ExchangingCredentials,
    JoiningHotspot,
    EstablishingSecureChannel,
    AwaitingTransferApproval { verification_code: String },
    Transferring,
    Completed,
    Failed { reason: String },
}