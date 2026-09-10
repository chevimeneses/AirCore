#![cfg(target_os = "windows")]

use aircore_core::discovery::{BleAdvertiser, AIRCORE_SERVICE_UUID};
use std::io;
use windows::Devices::Bluetooth::Advertisement::{
    BluetoothLEAdvertisement, BluetoothLEAdvertisementPublisher, BluetoothLEAdvertisementReceivedEventArgs,
    BluetoothLEAdvertisementWatcher, BluetoothLEManufacturerData,
};
use windows::Foundation::TypedEventHandler;
use windows::Storage::Streams::{DataReader, DataWriter};
use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
use windows::core::Ref;

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
        
        let bytes = AIRCORE_SERVICE_UUID.as_bytes();
        writer.WriteBytes(bytes).map_err(|e| win_err_ctx(e, "writer.WriteBytes"))?;
        let buffer = writer.DetachBuffer().map_err(|e| win_err_ctx(e, "DetachBuffer"))?;

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

/// Implementación del rol central BLE (escanear) para Windows,
/// buscando el ManufacturerData con ID 0xFFFF y el UUID de AirCore.
pub struct WindowsBleScanner {
    watcher: Option<BluetoothLEAdvertisementWatcher>,
}

impl WindowsBleScanner {
    pub fn new() -> Self {
        Self { watcher: None }
    }

    pub fn start_scanning<F>(&mut self, on_found: F) -> io::Result<()>
    where
        F: Fn(String, u64) + Send + 'static,
    {
        unsafe {
            let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
            if hr.is_err() && hr != windows::Win32::Foundation::RPC_E_CHANGED_MODE.into() {
                println!("[BLE Scanner] Advertencia: CoInitializeEx devolvió {:?}", hr);
            }
        }

        let watcher = BluetoothLEAdvertisementWatcher::new()
            .map_err(|e| win_err_ctx(e, "BluetoothLEAdvertisementWatcher::new"))?;

        let handler = TypedEventHandler::new(
            move |_: Ref<'_, BluetoothLEAdvertisementWatcher>, args: Ref<'_, BluetoothLEAdvertisementReceivedEventArgs>| {
                if let Some(args) = args.as_ref() {
                    if let Ok(advertisement) = args.Advertisement() {
                        if let Ok(mfg_list) = advertisement.ManufacturerData() {
                            if let Ok(size) = mfg_list.Size() {
                                for i in 0..size {
                                    if let Ok(mfg_data) = mfg_list.GetAt(i) {
                                        if let Ok(company_id) = mfg_data.CompanyId() {
                                            if company_id == 0xFFFF {
                                                if let Ok(buffer) = mfg_data.Data() {
                                                    if let Ok(reader) = DataReader::FromBuffer(&buffer) {
                                                        let mut bytes = [0u8; 16];
                                                        if let Ok(len) = reader.UnconsumedBufferLength() {
                                                            if len >= 16 {
                                                                if reader.ReadBytes(&mut bytes).is_ok() {
                                                                    if bytes == *AIRCORE_SERVICE_UUID.as_bytes() {
                                                                        let bt_addr = args.BluetoothAddress().unwrap_or_default();
                                                                        let name = advertisement
                                                                            .LocalName()
                                                                            .map(|n| n.to_string())
                                                                            .unwrap_or_else(|_| "AirCore-Receiver".to_string());
                                                                        
                                                                        on_found(name, bt_addr);
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(())
            },
        );

        watcher
            .Received(&handler)
            .map_err(|e| win_err_ctx(e, "Watcher.Received subscription"))?;

        watcher.Start().map_err(|e| win_err_ctx(e, "watcher.Start"))?;
        println!("[BLE Scanner] Escaneo iniciado correctamente...");
        
        self.watcher = Some(watcher);
        Ok(())
    }

    pub fn stop_scanning(&mut self) -> io::Result<()> {
        if let Some(watcher) = self.watcher.take() {
            watcher.Stop().map_err(win_err)?;
            println!("[BLE Scanner] Escaneo detenido correctamente.");
        }
        Ok(())
    }
}