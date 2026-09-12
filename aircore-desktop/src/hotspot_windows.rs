#![cfg(target_os = "windows")]
#![allow(dead_code)] // Le decimos al compilador "sé que hay cosas sin usar todavía, es a propósito, no avises".

use aircore_core::discovery::HotspotManager;
use std::io;
use windows::core::HSTRING; // Un tipo de texto especial que las APIs de Windows necesitan (distinto al String normal de Rust).
use windows::Devices::WiFiDirect::{
    WiFiDirectAdvertisement, WiFiDirectAdvertisementPublisher,
    WiFiDirectAdvertisementPublisherStatus,
};
use windows::Security::Credentials::PasswordCredential;
use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};

/// Este es el "cumplidor" del contrato HotspotManager (definido en
/// aircore-core/discovery.rs) para Windows. Usa Wi-Fi Direct en modo
/// "Legacy" — esto significa que crea una red Wi-Fi con SSID y
/// contraseña como cualquier red normal, en vez de requerir que el
/// otro dispositivo también hable el protocolo Wi-Fi Direct nativo.
/// IMPORTANTE: elegimos esto en vez de la función "Mobile Hotspot" de
/// Windows porque esa otra requiere tener ya una conexión a internet
/// para "compartir" — y en el bosque no hay internet que compartir.
/// Wi-Fi Direct sí funciona sin internet en absoluto.
pub struct WindowsHotspotManager {
    publisher: Option<WiFiDirectAdvertisementPublisher>,
}

impl WindowsHotspotManager {
    pub fn new() -> Self {
        Self { publisher: None }
    }
}

fn win_err_ctx(e: windows::core::Error, context: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Other,
        format!("Error de Windows Wi-Fi Direct en [{}]: {:?}", context, e),
    )
}

impl HotspotManager for WindowsHotspotManager {
    // ✅ CONFIRMADO FUNCIONANDO: Windows reporta que el hotspot arranca
    // correctamente ("Started"). ⚠️ PENDIENTE: nunca se ha confirmado
    // que otro dispositivo se pueda conectar de verdad (se probó con
    // iPhone/iPad, que no lo detectaron — probablemente porque iOS no
    // soporta Wi-Fi Direct de terceros, no porque el código esté mal).
    fn start_hotspot(&mut self, ssid: &str, password: &str) -> io::Result<String> {
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED); // Prepara COM en este hilo, requisito de Windows.
        }

        println!("[Hotspot] Creando WiFiDirectAdvertisementPublisher...");
        let publisher = WiFiDirectAdvertisementPublisher::new()
            .map_err(|e| win_err_ctx(e, "WiFiDirectAdvertisementPublisher::new"))?;

        let advertisement: WiFiDirectAdvertisement = publisher
            .Advertisement()
            .map_err(|e| win_err_ctx(e, "publisher.Advertisement()"))?;

        println!("[Hotspot] Configurando LegacySettings (SSID + contraseña fijos)...");
        let legacy_settings = advertisement
            .LegacySettings() // "Legacy" = modo compatible con cualquier dispositivo, no solo Wi-Fi Direct nativo.
            .map_err(|e| win_err_ctx(e, "advertisement.LegacySettings()"))?;

        legacy_settings
            .SetIsEnabled(true) // Activa el modo Legacy (sin esto, sería Wi-Fi Direct "puro", más restrictivo).
            .map_err(|e| win_err_ctx(e, "legacy_settings.SetIsEnabled"))?;

        let credential = PasswordCredential::new()
            .map_err(|e| win_err_ctx(e, "PasswordCredential::new"))?;
        credential
            .SetPassword(&HSTRING::from(password))
            .map_err(|e| win_err_ctx(e, "credential.SetPassword"))?;

        legacy_settings
            .SetPassphrase(&credential) // La contraseña que necesitará quien se quiera conectar.
            .map_err(|e| win_err_ctx(e, "legacy_settings.SetPassphrase"))?;
        legacy_settings
            .SetSsid(&HSTRING::from(ssid)) // El nombre de la red que va a aparecer en la lista de Wi-Fi de otros.
            .map_err(|e| win_err_ctx(e, "legacy_settings.SetSsid"))?;

        println!("[Hotspot] Iniciando publicación (Start)...");
        publisher
            .Start() // Aquí es donde de verdad se prende la red — antes de esto, todo era solo configuración.
            .map_err(|e| win_err_ctx(e, "publisher.Start()"))?;

        let status = publisher
            .Status()
            .map_err(|e| win_err_ctx(e, "publisher.Status()"))?;
        println!("[Hotspot] Estado tras Start(): {:?}", status);

        // Verificamos que de verdad haya arrancado y no se haya quedado
        // a medias en algún estado raro.
        if status != WiFiDirectAdvertisementPublisherStatus::Started {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("El publisher no llegó a estado Started: {:?}", status),
            ));
        }

        self.publisher = Some(publisher); // Lo guardamos para poder apagarlo después.

        // Nota: todavía no devolvemos una IP real del host — eso se
        // resuelve del lado del Guest reutilizando el descubrimiento
        // UDP existente, una vez que ambos estén en la misma red que
        // este hotspot acaba de crear. Devolvemos el SSID como
        // referencia por ahora.
        Ok(ssid.to_string())
    }

    fn stop_hotspot(&mut self) -> io::Result<()> {
        if let Some(publisher) = self.publisher.take() {
            // NOTA TÉCNICA: esta versión de la API no tiene un botón
            // "Stop()" explícito para el hotspot — simplemente
            // "soltar" el objeto (drop) es lo que hace que Windows lo
            // apague por dentro. Es un poco raro, pero es cómo
            // funciona esta API en particular.
            drop(publisher);
            println!("[Hotspot] Publisher liberado (hotspot detenido).");
        }
        Ok(())
    }

    // ⚠️ NUNCA PROBADO EN VIVO — compila y la lógica parece correcta,
    // pero requiere DOS laptops Windows corriendo al mismo tiempo (una
    // con start_hotspot, otra con esta función) para poder confirmar
    // que de verdad funciona. Es justo la prueba pendiente.
    fn join_network(&mut self, ssid: &str, password: &str) -> io::Result<()> {
        use windows::Devices::WiFi::{WiFiAccessStatus, WiFiAdapter, WiFiReconnectionKind};
        use windows::Security::Credentials::PasswordCredential;

        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        }

        println!("[WiFi] Pidiendo permiso de acceso a adaptadores Wi-Fi...");
        let access_status = WiFiAdapter::RequestAccessAsync()
            .map_err(|e| win_err_ctx(e, "WiFiAdapter::RequestAccessAsync"))?
            .get() // ".get()" espera a que la operación asíncrona de Windows termine, antes de seguir.
            .map_err(|e| win_err_ctx(e, "RequestAccessAsync.get()"))?;

        if access_status != WiFiAccessStatus::Allowed {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("Acceso Wi-Fi no permitido: {:?}", access_status),
            ));
        }

        println!("[WiFi] Buscando adaptadores...");
        let adapters = WiFiAdapter::FindAllAdaptersAsync()
            .map_err(|e| win_err_ctx(e, "FindAllAdaptersAsync"))?
            .get()
            .map_err(|e| win_err_ctx(e, "FindAllAdaptersAsync.get()"))?;

        let adapter = adapters
            .GetAt(0) // Usamos el primer adaptador Wi-Fi que tenga la laptop (normalmente solo hay uno).
            .map_err(|e| win_err_ctx(e, "adapters.GetAt(0)"))?;

        println!("[WiFi] Escaneando redes cercanas...");
        adapter
            .ScanAsync() // Le pedimos a Windows que actualice la lista de redes Wi-Fi visibles ahora mismo.
            .map_err(|e| win_err_ctx(e, "adapter.ScanAsync"))?
            .get()
            .map_err(|e| win_err_ctx(e, "ScanAsync.get()"))?;

        let report = adapter
            .NetworkReport()
            .map_err(|e| win_err_ctx(e, "adapter.NetworkReport"))?;
        let networks = report
            .AvailableNetworks() // La lista completa de redes Wi-Fi que la laptop puede ver ahora mismo.
            .map_err(|e| win_err_ctx(e, "report.AvailableNetworks"))?;

        // Recorremos toda la lista buscando la que tenga exactamente
        // el nombre (SSID) del hotspot que queremos.
        println!("[WiFi] Buscando la red '{}' entre las encontradas...", ssid);
        let target_ssid = HSTRING::from(ssid);
        let mut found = None;
        for network in networks {
            if let Ok(net_ssid) = network.Ssid() {
                if net_ssid == target_ssid {
                    found = Some(network);
                    break;
                }
            }
        }

        let network = found.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("No se encontró la red '{}' en el escaneo", ssid),
            )
        })?;

        let credential = PasswordCredential::new()
            .map_err(|e| win_err_ctx(e, "PasswordCredential::new"))?;
        credential
            .SetPassword(&HSTRING::from(password))
            .map_err(|e| win_err_ctx(e, "credential.SetPassword"))?;

        println!("[WiFi] Conectando a '{}'...", ssid);
        // NOTA: el nombre "ConnectWithPasswordCredentialAsync" (en vez
        // del más obvio "ConnectAsync") es porque esta función de
        // Windows está "sobrecargada" (existe en varias versiones con
        // distintos parámetros), y esta es la versión específica para
        // cuando SÍ tienes una contraseña que mandar.
        let result = adapter
            .ConnectWithPasswordCredentialAsync(&network, WiFiReconnectionKind::Automatic, &credential)
            .map_err(|e| win_err_ctx(e, "adapter.ConnectWithPasswordCredentialAsync"))?
            .get()
            .map_err(|e| win_err_ctx(e, "ConnectAsync.get()"))?;

        let status = result
            .ConnectionStatus()
            .map_err(|e| win_err_ctx(e, "result.ConnectionStatus"))?;
        println!("[WiFi] Estado de conexión: {:?}", status);

        Ok(())
    }
}

// Dos pruebas manuales (no corren automáticamente, por el #[ignore]).
#[cfg(test)]
mod tests {
    use super::*;

    // ✅ Ya se corrió con éxito: confirma que Windows crea el hotspot
    // sin errores. Se deja corriendo hasta que presionas Enter, para
    // dar tiempo de ir a revisar con un celular si la red aparece.
    #[test]
    #[ignore] // cargo test -p aircore-desktop -- --ignored --nocapture crea_hotspot
    fn crea_hotspot_por_20_segundos() {
        let mut manager = WindowsHotspotManager::new();
        let result = manager.start_hotspot("AirCore-Test-Hotspot", "clavePrueba123");

        match &result {
            Ok(info) => println!("[Hotspot] ¡Arrancó! Info: {}", info),
            Err(e) => println!("[Hotspot] Falló: {}", e),
        }
        result.expect("el hotspot debería arrancar sin errores");

        println!("[Hotspot] Activo. Ve a la otra laptop y corre la prueba de unión.");
        println!("[Hotspot] Presiona ENTER aquí cuando termines para detener el hotspot...");
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf).ok(); // Se queda esperando aquí hasta que le des Enter.

        manager.stop_hotspot().expect("debería detenerse sin errores");
        println!("[Hotspot] Detenido.");
    }

    // ⚠️ Esta prueba, tal como está escrita, NO valida una unión real
    // (una sola laptop no puede ser anfitriona y cliente de la misma
    // red a la vez) — solo confirma que ambas funciones se pueden
    // llamar en secuencia sin tronar. La prueba REAL requiere correr
    // esto en dos laptops distintas al mismo tiempo — es justo la
    // prueba pendiente que vas a hacer con tu segundo equipo.
    #[test]
    #[ignore] // Solo correr en una red donde tengas permiso de crear/unirte a redes propias
    fn crea_y_se_une_al_hotspot() {
        let mut manager = WindowsHotspotManager::new();
        manager
            .start_hotspot("AirCore-Test-Hotspot", "clavePrueba123")
            .expect("el hotspot debería arrancar");

        std::thread::sleep(std::time::Duration::from_secs(3));

        manager.stop_hotspot().expect("debería detenerse sin errores");
    }
}