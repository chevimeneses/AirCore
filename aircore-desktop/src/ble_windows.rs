#![cfg(target_os = "windows")]

use aircore_core::discovery::{BleAdvertiser, AIRCORE_SERVICE_UUID};
use std::io;
use windows::Devices::Bluetooth::Advertisement::{
    BluetoothLEAdvertisement, BluetoothLEAdvertisementPublisher, BluetoothLEManufacturerData,
};
use windows::Storage::Streams::DataWriter;
use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};

/// Implementación del rol periférico BLE (anunciarse) para Windows,
/// usando la API de Windows Runtime a través de windows-rs mediante ManufacturerData.
pub struct WindowsBleAdvertiser {
    publisher: Option<BluetoothLEAdvertisementPublisher>,
}

impl WindowsBleAdvertiser {
    pub fn new() -> Self {
        Self { publisher: None }
    }
}

fn win_err(e: windows::core::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("Error de Windows Bluetooth: {:?}", e))
}

fn win_err_ctx(e: windows::core::Error, context: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Other,
        format!("Error de Windows Bluetooth en [{}]: {:?}", context, e),
    )
}

impl BleAdvertiser for WindowsBleAdvertiser {
    fn start_advertising(&mut self, device_name: &str) -> io::Result<()> {
        let _ = device_name;

        // Inicializa COM/WinRT en este hilo. Si ya estaba inicializado
        // (RPC_E_CHANGED_MODE) lo ignoramos.
        unsafe {
            let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
            if hr.is_err() && hr != windows::Win32::Foundation::RPC_E_CHANGED_MODE.into() {
                println!("[BLE] Advertencia: CoInitializeEx devolvió {:?}", hr);
            }
        }

        println!("[BLE] Creando objeto BluetoothLEAdvertisement...");
        let advertisement = BluetoothLEAdvertisement::new()
            .map_err(|e| win_err_ctx(e, "BluetoothLEAdvertisement::new"))?;
        println!("[BLE] OK");

        println!("[BLE] Empaquetando UUID de AirCore en ManufacturerData...");
        let writer = DataWriter::new().map_err(|e| win_err_ctx(e, "DataWriter::new"))?;
        
        // Escribimos los 16 bytes crudos del UUID del servicio dentro del payload
        let bytes = AIRCORE_SERVICE_UUID.as_bytes();
        writer.WriteBytes(bytes).map_err(|e| win_err_ctx(e, "writer.WriteBytes"))?;
        let buffer = writer.DetachBuffer().map_err(|e| win_err_ctx(e, "DetachBuffer"))?;

        // 0xFFFF es el ID de compañía reservado para pruebas y desarrollo local
        let mfg_data = BluetoothLEManufacturerData::Create(0xFFFF, &buffer)
            .map_err(|e| win_err_ctx(e, "BluetoothLEManufacturerData::Create"))?;

        advertisement
            .ManufacturerData()
            .map_err(|e| win_err_ctx(e, "advertisement.ManufacturerData()"))?
            .Append(&mfg_data)
            .map_err(|e| win_err_ctx(e, "ManufacturerData.Append"))?;
        println!("[BLE] OK");

        println!("[BLE] Creando Publisher...");
        let publisher = BluetoothLEAdvertisementPublisher::Create(&advertisement)
            .map_err(|e| win_err_ctx(e, "BluetoothLEAdvertisementPublisher::Create"))?;
        println!("[BLE] OK");

        println!("[BLE] Llamando Start()...");
        publisher
            .Start()
            .map_err(|e| win_err_ctx(e, "publisher.Start()"))?;
        println!("[BLE] OK — anuncio iniciado correctamente");

        self.publisher = Some(publisher);
        Ok(())
    }

    fn stop_advertising(&mut self) -> io::Result<()> {
        if let Some(publisher) = self.publisher.take() {
            publisher.Stop().map_err(win_err)?;
            println!("[BLE] Anuncio detenido correctamente.");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    #[ignore] // cargo test -p aircore-desktop -- --ignored --nocapture anuncia_por_10_segundos
    fn anuncia_por_10_segundos() {
        let mut advertiser = WindowsBleAdvertiser::new();
        advertiser
            .start_advertising("AirCore-Test")
            .expect("el anuncio debería iniciar sin errores");

        println!("Anunciando como 'AirCore-Test' por 10 segundos...");
        sleep(Duration::from_secs(10));

        advertiser.stop_advertising().expect("debería detenerse sin errores");
    }

    #[test]
    #[ignore] // cargo test -p aircore-desktop -- --ignored --nocapture diagnostica_soporte_periferico
    fn diagnostica_soporte_periferico() {
        use windows::Devices::Bluetooth::BluetoothAdapter;

        let adapter = BluetoothAdapter::GetDefaultAsync()
            .expect("no se pudo iniciar GetDefaultAsync")
            .get()
            .expect("no se pudo obtener el adaptador Bluetooth");

        let central = adapter
            .IsCentralRoleSupported()
            .expect("no se pudo leer IsCentralRoleSupported");
        let peripheral = adapter
            .IsPeripheralRoleSupported()
            .expect("no se pudo leer IsPeripheralRoleSupported");

        println!("¿Soporta rol central (escanear)?   {}", central);
        println!("¿Soporta rol periférico (anunciar)? {}", peripheral);
    }
}