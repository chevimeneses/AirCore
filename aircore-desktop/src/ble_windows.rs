// #![cfg(target_os = "windows")] significa: "todo este archivo solo
// existe y se compila si estamos armando la app para Windows". Si
// algún día se compila para Linux o macOS, este archivo entero se
// ignora, como si no existiera.
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

// ⚠️ ESTA STRUCT (WindowsBleAdvertiser) YA NO SE USA EN LA APP REAL.
// Fue el PRIMER intento de "anunciarse por Bluetooth" que construimos,
// usando un truco llamado ManufacturerData (esconder el UUID de
// AirCore dentro de un campo pensado para otra cosa). Funcionó, pero
// quedó reemplazada por WindowsGattServer (en otro archivo), que hace
// lo mismo pero de la forma "correcta" (con un servicio GATT real,
// que además permite recibir conexiones, no solo anunciarse). Se dejó
// aquí como referencia histórica de cómo se resolvió el primer bug
// de compilación (0x80070057), por si algún día hace falta un
// anuncio "ligero" sin GATT completo.
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

// Como win_err, pero agrega en qué paso exacto ocurrió el error — esto
// se agregó cuando estábamos depurando el bug 0x80070057 y necesitábamos
// saber CUÁL de varias llamadas seguidas estaba fallando.
fn win_err_ctx(e: windows::core::Error, context: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Other,
        format!("Error de Windows Bluetooth en [{}]: {:?}", context, e),
    )
}

impl BleAdvertiser for WindowsBleAdvertiser {
    fn start_advertising(&mut self, device_name: &str) -> io::Result<()> {
        let _ = device_name; // No se usa: el nombre no cabía en el paquete de anuncio junto con el UUID.

        // COM es un sistema de Windows que necesita "prepararse" antes
        // de que este hilo pueda hablar con APIs modernas como
        // Bluetooth. Si ya estaba preparado (RPC_E_CHANGED_MODE), no
        // es un error real, solo lo avisamos por si acaso.
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

        // Truco: en vez de anunciar el UUID de AirCore de la forma
        // "normal" (que causaba el bug 0x80070057 por un problema de
        // conversión de bytes), lo escondemos dentro de un campo
        // llamado "ManufacturerData", usando el ID 0xFFFF — que está
        // oficialmente reservado por Bluetooth para pruebas, así que
        // no choca con ningún fabricante real.
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

        self.publisher = Some(publisher); // Lo guardamos para poder detenerlo después.
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

/// ✅ ESTA SÍ SE USA ACTIVAMENTE — es el escáner real detrás del botón
/// "📶 Buscar BLE" en la app. Busca dispositivos que estén anunciando
/// el mismo truco de ManufacturerData de arriba, y avisa cada vez que
/// encuentra uno con el UUID correcto de AirCore.
pub struct WindowsBleScanner {
    watcher: Option<BluetoothLEAdvertisementWatcher>,
}

impl WindowsBleScanner {
    pub fn new() -> Self {
        Self { watcher: None }
    }

    // "on_found" es una función que TÚ le pasas desde afuera (desde
    // main.rs), y que esta función llama automáticamente cada vez que
    // detecta un dispositivo AirCore — así main.rs no tiene que saber
    // nada de los detalles de Bluetooth, solo recibe "encontré a
    // fulano en esta dirección".
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

        // Este "handler" es código que Windows va a ejecutar
        // automáticamente, EN SEGUNDO PLANO, cada vez que detecte
        // CUALQUIER anuncio Bluetooth cercano (no solo los de
        // AirCore) — por eso adentro hay que revisar manualmente si
        // el anuncio que llegó es realmente de AirCore o de otra cosa
        // (un audífono, un celular, etc).
        let handler = TypedEventHandler::new(
            move |_: Ref<'_, BluetoothLEAdvertisementWatcher>, args: Ref<'_, BluetoothLEAdvertisementReceivedEventArgs>| {
                if let Some(args) = args.as_ref() {
                    if let Ok(advertisement) = args.Advertisement() {
                        if let Ok(mfg_list) = advertisement.ManufacturerData() {
                            if let Ok(size) = mfg_list.Size() {
                                // Un anuncio puede traer varios "ManufacturerData" distintos
                                // (de distintos fabricantes) — revisamos todos.
                                for i in 0..size {
                                    if let Ok(mfg_data) = mfg_list.GetAt(i) {
                                        if let Ok(company_id) = mfg_data.CompanyId() {
                                            // ¿Es del ID reservado de pruebas que usamos nosotros?
                                            if company_id == 0xFFFF {
                                                if let Ok(buffer) = mfg_data.Data() {
                                                    if let Ok(reader) = DataReader::FromBuffer(&buffer) {
                                                        let mut bytes = [0u8; 16];
                                                        if let Ok(len) = reader.UnconsumedBufferLength() {
                                                            if len >= 16 {
                                                                if reader.ReadBytes(&mut bytes).is_ok() {
                                                                    // ¿El UUID que trae adentro es EXACTAMENTE
                                                                    // el de AirCore, y no coincidencia?
                                                                    if bytes == *AIRCORE_SERVICE_UUID.as_bytes() {
                                                                        let bt_addr = args.BluetoothAddress().unwrap_or_default();
                                                                        let name = advertisement
                                                                            .LocalName()
                                                                            .map(|n| n.to_string())
                                                                            .unwrap_or_else(|_| "AirCore-Receiver".to_string());

                                                                        // ¡Encontramos uno de verdad! Avisamos a quien
                                                                        // nos esté escuchando (main.rs, normalmente).
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

        watcher.Start().map_err(|e| win_err_ctx(e, "watcher.Start"))?; // Ahora sí, empieza a escuchar de verdad.
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