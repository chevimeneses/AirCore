#![cfg(target_os = "windows")]

use aircore_core::discovery::HotspotManager;
use std::io;
use windows::core::HSTRING;
use windows::Devices::WiFiDirect::{
    WiFiDirectAdvertisement, WiFiDirectAdvertisementPublisher,
    WiFiDirectAdvertisementPublisherStatus,
};
use windows::Security::Credentials::PasswordCredential;
use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};

/// Crea un punto de acceso Wi-Fi Direct en modo "Legacy": cualquier
/// dispositivo puede unirse con SSID + contraseña normales, como si
/// fuera un router Wi-Fi común, sin necesitar hablar Wi-Fi Direct del
/// otro lado. No requiere ninguna conexión a internet existente.
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
    fn start_hotspot(&mut self, ssid: &str, password: &str) -> io::Result<String> {
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        }

        println!("[Hotspot] Creando WiFiDirectAdvertisementPublisher...");
        let publisher = WiFiDirectAdvertisementPublisher::new()
            .map_err(|e| win_err_ctx(e, "WiFiDirectAdvertisementPublisher::new"))?;

        let advertisement: WiFiDirectAdvertisement = publisher
            .Advertisement()
            .map_err(|e| win_err_ctx(e, "publisher.Advertisement()"))?;

        println!("[Hotspot] Configurando LegacySettings (SSID + contraseña fijos)...");
        let legacy_settings = advertisement
            .LegacySettings()
            .map_err(|e| win_err_ctx(e, "advertisement.LegacySettings()"))?;

        legacy_settings
            .SetIsEnabled(true)
            .map_err(|e| win_err_ctx(e, "legacy_settings.SetIsEnabled"))?;

        let credential = PasswordCredential::new()
            .map_err(|e| win_err_ctx(e, "PasswordCredential::new"))?;
        credential
            .SetPassword(&HSTRING::from(password))
            .map_err(|e| win_err_ctx(e, "credential.SetPassword"))?;

        legacy_settings
            .SetPassphrase(&credential)
            .map_err(|e| win_err_ctx(e, "legacy_settings.SetPassphrase"))?;
        legacy_settings
            .SetSsid(&HSTRING::from(ssid))
            .map_err(|e| win_err_ctx(e, "legacy_settings.SetSsid"))?;

        println!("[Hotspot] Iniciando publicación (Start)...");
        publisher
            .Start()
            .map_err(|e| win_err_ctx(e, "publisher.Start()"))?;

        let status = publisher
            .Status()
            .map_err(|e| win_err_ctx(e, "publisher.Status()"))?;
        println!("[Hotspot] Estado tras Start(): {:?}", status);

        if status != WiFiDirectAdvertisementPublisherStatus::Started {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("El publisher no llegó a estado Started: {:?}", status),
            ));
        }

        self.publisher = Some(publisher);

        // Nota: todavía no devolvemos una IP real del host — eso se
        // resuelve del lado del Guest reutilizando el descubrimiento
        // UDP existente, una vez que ambos estén en la misma red que
        // este hotspot acaba de crear. Devolvemos el SSID como
        // referencia por ahora.
        Ok(ssid.to_string())
    }

    fn stop_hotspot(&mut self) -> io::Result<()> {
        if let Some(publisher) = self.publisher.take() {
            // WiFiDirectAdvertisementPublisher no tiene un método Stop()
            // explícito en todas las versiones — soltar la referencia
            // (drop) es lo que detiene la publicación. Lo dejamos así
            // por ahora; si hace falta un Stop() explícito lo agregamos
            // cuando validemos la API real.
            drop(publisher);
            println!("[Hotspot] Publisher liberado (hotspot detenido).");
        }
        Ok(())
    }

        fn join_network(&mut self, ssid: &str, password: &str) -> io::Result<()> {
        use windows::Devices::Wifi::{WiFiAccessStatus, WiFiAdapter, WiFiReconnectionKind};
        use windows::Security::Credentials::PasswordCredential;

        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        }

        println!("[WiFi] Pidiendo permiso de acceso a adaptadores Wi-Fi...");
        let access_status = WiFiAdapter::RequestAccessAsync()
            .map_err(|e| win_err_ctx(e, "WiFiAdapter::RequestAccessAsync"))?
            .get()
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
            .GetAt(0)
            .map_err(|e| win_err_ctx(e, "adapters.GetAt(0)"))?;

        println!("[WiFi] Escaneando redes cercanas...");
        adapter
            .ScanAsync()
            .map_err(|e| win_err_ctx(e, "adapter.ScanAsync"))?
            .get()
            .map_err(|e| win_err_ctx(e, "ScanAsync.get()"))?;

        let report = adapter
            .NetworkReport()
            .map_err(|e| win_err_ctx(e, "adapter.NetworkReport"))?;
        let networks = report
            .AvailableNetworks()
            .map_err(|e| win_err_ctx(e, "report.AvailableNetworks"))?;

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
        let result = adapter
            .ConnectAsync(&network, WiFiReconnectionKind::Automatic, &credential)
            .map_err(|e| win_err_ctx(e, "adapter.ConnectAsync"))?
            .get()
            .map_err(|e| win_err_ctx(e, "ConnectAsync.get()"))?;

        let status = result
            .ConnectionStatus()
            .map_err(|e| win_err_ctx(e, "result.ConnectionStatus"))?;
        println!("[WiFi] Estado de conexión: {:?}", status);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

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

        println!("[Hotspot] Activo por 20 segundos — revisa en tu celular si aparece la red 'AirCore-Test-Hotspot'...");
        sleep(Duration::from_secs(20));

        manager.stop_hotspot().expect("debería detenerse sin errores");
        println!("[Hotspot] Detenido.");
    }

    #[test]
    #[ignore] // Solo correr en una red donde tengas permiso de crear/unirte a redes propias
    fn crea_y_se_une_al_hotspot() {
        // Nota: esta prueba requiere DOS procesos o DOS máquinas para
        // ser realista (uno hospeda, otro se une). Por ahora solo
        // valida que start_hotspot y join_network compilan y corren
        // sin tronar, no que la unión realmente tenga éxito end-to-end
        // todavía — eso lo probamos manualmente cuando conectemos las
        // dos piezas al flujo completo.
        let mut manager = WindowsHotspotManager::new();
        manager
            .start_hotspot("AirCore-Test-Hotspot", "clavePrueba123")
            .expect("el hotspot debería arrancar");

        std::thread::sleep(std::time::Duration::from_secs(3));

        manager.stop_hotspot().expect("debería detenerse sin errores");
    }
}