use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter};
use btleplug::platform::Manager;
use std::io;
use std::time::Duration;
use tokio::runtime::Runtime;
use uuid::Uuid;

// Este es el "código secreto" que usan todos los dispositivos AirCore
// para reconocerse entre sí durante un escaneo BLE — como una frase
// clave que solo entienden los dispositivos que corren esta app. No
// importa si otras apps la ven; simplemente la ignorarán porque no la
// reconocen.
pub const AIRCORE_SERVICE_UUID: Uuid = Uuid::from_u128(0x8a51ec228f744d2e9e299f1e2b9d5c31);

/// Representa un dispositivo AirCore que encontramos mientras
/// escaneábamos por Bluetooth — solo guarda datos, no hace nada por
/// sí solo.
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    pub name: String,
    pub address: String,
    pub signal_strength: Option<i16>, // RSSI: qué tan fuerte se oye la señal (más cercano a 0 = más cerca).
}

// ⚠️ Los siguientes tres "traits" son solo CONTRATOS — como una receta
// que dice "cualquier implementación de esto debe saber hacer tal
// cosa", pero sin decir CÓMO. Son el plano de diseño; la
// implementación real de cada uno vive en archivos específicos de
// Windows (ble_windows.rs, hotspot_windows.rs), porque cada sistema
// operativo tiene su propia forma de hacer estas cosas.

/// Contrato: "anunciarse por Bluetooth para que otros te encuentren".
/// NO tiene implementación aquí — hoy solo lo cumple WindowsGattServer
/// en aircore-desktop, indirectamente (usa su propio mecanismo, no
/// implementa este trait literalmente, pero cumple el mismo propósito).
pub trait BleAdvertiser: Send {
    fn start_advertising(&mut self, device_name: &str) -> io::Result<()>;
    fn stop_advertising(&mut self) -> io::Result<()>;
}

/// Contrato: "buscar dispositivos AirCore cercanos por Bluetooth".
pub trait BleScanner: Send {
    fn scan(&mut self, timeout_secs: u64) -> io::Result<Vec<DiscoveredPeer>>;
}

/// Contrato: "crear/destruir un Wi-Fi temporal, y poder unirse a uno".
/// Implementado de verdad en hotspot_windows.rs (WindowsHotspotManager).
pub trait HotspotManager: Send {
    fn start_hotspot(&mut self, ssid: &str, password: &str) -> io::Result<String>;
    fn stop_hotspot(&mut self) -> io::Result<()>;
    fn join_network(&mut self, ssid: &str, password: &str) -> io::Result<()>;
}

/// ✅ ESTA SÍ es una implementación real y funcional (no solo un
/// contrato) — usa la librería "btleplug", que funciona igual en
/// Windows, macOS, Linux y Android. Es la única pieza de todo BLE que
/// no depende de código específico de un sistema operativo.
///
/// NOTA IMPORTANTE: aunque esta implementación existe y funciona
/// (fue probada escaneando dispositivos Bluetooth reales), main.rs
/// NO la está usando hoy — en su lugar usa WindowsBleScanner (nativo
/// de Windows) para la búsqueda real desde la interfaz. Esta clase se
/// queda aquí como la opción "multiplataforma" para el día que se
/// quiera portar el proyecto a Linux/macOS/Android, donde la versión
/// nativa de Windows no compilaría.
pub struct BtleplugScanner;

impl BtleplugScanner {
    pub fn new() -> Self {
        Self
    }

    /// Escanea CUALQUIER dispositivo BLE cercano (celulares, audífonos,
    /// lo que sea), sin filtrar por el UUID de AirCore. Sirve para
    /// confirmar que el Bluetooth de la máquina funciona en general.
    pub fn scan_any(&mut self, timeout_secs: u64) -> io::Result<Vec<DiscoveredPeer>> {
        // btleplug funciona de forma "asíncrona" (async), pero el
        // resto de nuestro proyecto trabaja de forma normal/síncrona.
        // Este Runtime es el "traductor" que permite llamar código
        // async desde código normal, esperando a que termine antes de
        // seguir (block_on = "bloquéate aquí hasta que esto acabe").
        let rt = Runtime::new().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        rt.block_on(async {
            let manager = Manager::new().await.map_err(ble_err)?;
            let adapters = manager.adapters().await.map_err(ble_err)?; // Los "radios" Bluetooth de esta PC.
            let central = adapters.into_iter().next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "No se encontró ningún adaptador Bluetooth")
            })?; // Usamos el primero que haya (normalmente solo hay uno).

            central.start_scan(ScanFilter::default()).await.map_err(ble_err)?; // Empieza a escuchar el aire.
            tokio::time::sleep(Duration::from_secs(timeout_secs)).await; // Espera el tiempo pedido.

            let peripherals = central.peripherals().await.map_err(ble_err)?; // Todo lo que se detectó.
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
            let _ = central.stop_scan().await; // Apaga el escaneo, ya terminamos.
            Ok(result)
        })
    }
}

// Esto es lo que hace que BtleplugScanner "cumpla" oficialmente el
// contrato BleScanner de arriba.
impl BleScanner for BtleplugScanner {
    fn scan(&mut self, timeout_secs: u64) -> io::Result<Vec<DiscoveredPeer>> {
        // Por ahora es idéntico a scan_any (sin filtrar). El día que
        // se quiera usar esta clase de verdad en la app, aquí se
        // agregaría un filtro para solo devolver dispositivos que
        // anuncien AIRCORE_SERVICE_UUID, en vez de traer TODO lo que
        // haya cerca (celulares, audífonos, refrigeradores, etc).
        self.scan_any(timeout_secs)
    }
}

fn ble_err(e: btleplug::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("Error BLE: {:?}", e))
}

// Prueba manual (no corre automáticamente, por el #[ignore]) que ya
// se usó para confirmar que el escaneo BLE funciona de verdad en la
// laptop de desarrollo — encontró 17 dispositivos reales la primera
// vez que se corrió.
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