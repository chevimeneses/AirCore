use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter};
use btleplug::platform::Manager;
use std::io;
use std::time::Duration;
use tokio::runtime::Runtime;
use uuid::Uuid;

/// UUID de servicio propio de AirCore. Cualquier UUID único sirve;
/// este es fijo para que todos los dispositivos AirCore se reconozcan
/// entre sí durante el escaneo BLE. (Placeholder — se puede regenerar
/// más adelante, lo único que importa es que sea el mismo en todos
/// los dispositivos que corran esta app).
pub const AIRCORE_SERVICE_UUID: Uuid = Uuid::from_u128(0x8a51ec228f744d2e9e299f1e2b9d5c31);

/// Un dispositivo AirCore descubierto por BLE.
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    pub name: String,
    pub address: String,
    pub signal_strength: Option<i16>, // RSSI, si está disponible
}

/// Anuncia este dispositivo como receptor disponible (rol periférico BLE).
/// Todavía sin implementación real — viene en el siguiente paso, y sí
/// va a requerir código específico por sistema operativo.
pub trait BleAdvertiser: Send {
    fn start_advertising(&mut self, device_name: &str) -> io::Result<()>;
    fn stop_advertising(&mut self) -> io::Result<()>;
}

/// Busca dispositivos AirCore cercanos (rol central BLE).
pub trait BleScanner: Send {
    fn scan(&mut self, timeout_secs: u64) -> io::Result<Vec<DiscoveredPeer>>;
}

/// Crea y destruye un hotspot Wi-Fi temporal.
pub trait HotspotManager: Send {
    fn start_hotspot(&mut self, ssid: &str, password: &str) -> io::Result<String>;
    fn stop_hotspot(&mut self) -> io::Result<()>;
    fn join_network(&mut self, ssid: &str, password: &str) -> io::Result<()>;
}

/// Implementación real de BleScanner usando btleplug. Soporta el rol
/// central en Windows, macOS, Linux y Android, así que vive aquí en
/// el core y se reutiliza tal cual en todas las plataformas.
pub struct BtleplugScanner;

impl BtleplugScanner {
    pub fn new() -> Self {
        Self
    }

    /// Escanea CUALQUIER dispositivo BLE cercano, sin filtrar por el
    /// servicio de AirCore. Sirve solo para validar que el hardware/stack
    /// Bluetooth de esta máquina funciona, antes de tener un Advertiser
    /// real que anuncie el servicio propio de AirCore.
    pub fn scan_any(&mut self, timeout_secs: u64) -> io::Result<Vec<DiscoveredPeer>> {
        let rt = Runtime::new().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        rt.block_on(async {
            let manager = Manager::new().await.map_err(ble_err)?;
            let adapters = manager.adapters().await.map_err(ble_err)?;
            let central = adapters.into_iter().next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "No se encontró ningún adaptador Bluetooth")
            })?;

            central.start_scan(ScanFilter::default()).await.map_err(ble_err)?;
            tokio::time::sleep(Duration::from_secs(timeout_secs)).await;

            let peripherals = central.peripherals().await.map_err(ble_err)?;
            let mut result = Vec::new();
            for p in peripherals {
                if let Ok(Some(props)) = p.properties().await {
                    result.push(DiscoveredPeer {
                        name: props.local_name.unwrap_or_else(|| "(sin nombre)".to_string()),
                        address: p.id().to_string(),
                        signal_strength: props.rssi,
                    });
                }
            }
            let _ = central.stop_scan().await;
            Ok(result)
        })
    }
}

impl BleScanner for BtleplugScanner {
    fn scan(&mut self, timeout_secs: u64) -> io::Result<Vec<DiscoveredPeer>> {
        // Por ahora idéntico a scan_any. En cuanto exista un Advertiser
        // real, aquí se filtra por AIRCORE_SERVICE_UUID.
        self.scan_any(timeout_secs)
    }
}

fn ble_err(e: btleplug::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("Error BLE: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // quítale el ignore para correrlo manualmente: cargo test -- --ignored --nocapture
    fn escanea_dispositivos_ble_reales() {
        let mut scanner = BtleplugScanner::new();
        let result = scanner.scan_any(5).expect("el escaneo no debería fallar");
        println!("Dispositivos encontrados: {}", result.len());
        for peer in &result {
            println!("  - {} ({}) RSSI: {:?}", peer.name, peer.address, peer.signal_strength);
        }
    }
}