#![cfg(target_os = "windows")]
#![allow(dead_code)]

use crate::ble_transport_windows::{decode_response, BleClientTransport, HotspotResponse};
use crate::gatt_server_windows::{uuid_to_guid, CREDENTIALS_CHARACTERISTIC_UUID, OFFER_CHARACTERISTIC_UUID};
use aircore_core::crypto::perform_handshake_initiator;
use aircore_core::discovery::AIRCORE_SERVICE_UUID;
use aircore_core::transfer::encode_metadata;
use std::io;
use windows::Devices::Bluetooth::BluetoothLEDevice;
use windows::Devices::Bluetooth::GenericAttributeProfile::{
    GattCharacteristic, GattClientCharacteristicConfigurationDescriptorValue,
    GattCommunicationStatus, GattValueChangedEventArgs,
};
use windows::Foundation::TypedEventHandler;
use windows::Storage::Streams::DataReader;
use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};

fn win_err_ctx(e: windows::core::Error, context: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Other,
        format!("Error de Windows GATT (cliente) en [{}]: {:?}", context, e),
    )
}

/// Este es el "lado que se conecta" — el que usa el Emisor para
/// hablarle al servidor GATT del Receptor. Es como un teléfono que
/// marca a un número específico, en vez de esperar a que le llamen.
pub struct WindowsGattClient {
    _device: BluetoothLEDevice, // El guion bajo al inicio del nombre significa "sé que no lo uso directamente,
                                 // pero necesito que siga viva mientras dure la conexión" — si se destruyera,
                                 // Windows podría cerrar la conexión Bluetooth sin avisar.
}

impl WindowsGattClient {
    /// ⚠️ NUNCA PROBADO EN VIVO (requiere que un WindowsGattServer real
    /// esté corriendo en otra máquina) — pero la lógica está completa:
    /// se conecta al dispositivo, encuentra el servicio de AirCore, y
    /// localiza sus dos características (oferta y credenciales).
    pub fn connect(bluetooth_address: u64) -> io::Result<(Self, BleClientTransport)> {
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        }

        println!("[GATT-cliente] Conectando a dirección {:#014x}...", bluetooth_address);
        let device = BluetoothLEDevice::FromBluetoothAddressAsync(bluetooth_address)
            .map_err(|e| win_err_ctx(e, "BluetoothLEDevice::FromBluetoothAddressAsync"))?
            .get()
            .map_err(|e| win_err_ctx(e, "FromBluetoothAddressAsync.get()"))?;

        // Le preguntamos al dispositivo "¿tienes el servicio de
        // AirCore?" — si el otro lado no está corriendo
        // WindowsGattServer, esto va a fallar aquí mismo.
        println!("[GATT-cliente] Buscando el servicio AirCore...");
        let services_result = device
            .GetGattServicesForUuidAsync(uuid_to_guid(AIRCORE_SERVICE_UUID))
            .map_err(|e| win_err_ctx(e, "GetGattServicesForUuidAsync"))?
            .get()
            .map_err(|e| win_err_ctx(e, "GetGattServicesForUuidAsync.get()"))?;

        let status = services_result
            .Status()
            .map_err(|e| win_err_ctx(e, "services_result.Status()"))?;
        if status != GattCommunicationStatus::Success {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("No se pudo obtener el servicio AirCore: {:?}", status),
            ));
        }

        let services = services_result
            .Services()
            .map_err(|e| win_err_ctx(e, "services_result.Services()"))?;
        let service = services
            .GetAt(0) // Nos quedamos con el primero (el otro lado solo debería tener uno).
            .map_err(|e| win_err_ctx(e, "services.GetAt(0) — ¿el Host está anunciando?"))?;

        // Ahora buscamos las dos características específicas dentro
        // de ese servicio, igual que buscar dos platillos específicos
        // dentro del menú.
        println!("[GATT-cliente] Buscando característica de oferta (canal saliente)...");
        let offer_result = service
            .GetCharacteristicsForUuidAsync(uuid_to_guid(OFFER_CHARACTERISTIC_UUID))
            .map_err(|e| win_err_ctx(e, "GetCharacteristicsForUuidAsync (offer)"))?
            .get()
            .map_err(|e| win_err_ctx(e, "offer GetCharacteristicsForUuidAsync.get()"))?;
        let offer_char: GattCharacteristic = offer_result
            .Characteristics()
            .map_err(|e| win_err_ctx(e, "offer_result.Characteristics()"))?
            .GetAt(0)
            .map_err(|e| win_err_ctx(e, "offer characteristics.GetAt(0)"))?;

        println!("[GATT-cliente] Buscando característica de credenciales (canal entrante)...");
        let cred_result = service
            .GetCharacteristicsForUuidAsync(uuid_to_guid(CREDENTIALS_CHARACTERISTIC_UUID))
            .map_err(|e| win_err_ctx(e, "GetCharacteristicsForUuidAsync (cred)"))?
            .get()
            .map_err(|e| win_err_ctx(e, "cred GetCharacteristicsForUuidAsync.get()"))?;
        let credentials_char = cred_result
            .Characteristics()
            .map_err(|e| win_err_ctx(e, "cred_result.Characteristics()"))?
            .GetAt(0)
            .map_err(|e| win_err_ctx(e, "cred characteristics.GetAt(0)"))?;

        // Creamos nuestro lado del "traductor" Noise-sobre-BLE. Este
        // manda escribiendo en offer_char; recibe a través de una
        // cola que se llena cuando el Host nos notifique algo por
        // credentials_char (ver el handler justo abajo).
        let (transport, tx) = BleClientTransport::new(offer_char);

        // Código que Windows ejecuta automáticamente cada vez que el
        // Host cambia el valor de la característica de credenciales
        // (es decir, cada vez que nos manda una notificación). Su
        // único trabajo: leer los bytes y avisarle al transporte.
        let handler = TypedEventHandler::new(
            move |_sender, args: windows::core::Ref<'_, GattValueChangedEventArgs>| {
                if let Some(args) = args.as_ref() {
                    if let Ok(value) = args.CharacteristicValue() {
                        if let Ok(reader) = DataReader::FromBuffer(&value) {
                            let len = reader.UnconsumedBufferLength().unwrap_or(0) as usize;
                            let mut bytes = vec![0u8; len];
                            if reader.ReadBytes(&mut bytes).is_ok() {
                                let _ = tx.send(bytes);
                            }
                        }
                    }
                }
                Ok(())
            },
        );
        credentials_char
            .ValueChanged(&handler) // "Avísame cada vez que cambie este valor".
            .map_err(|e| win_err_ctx(e, "credentials_char.ValueChanged"))?;

        // Suscribirse al handler de arriba NO BASTA — también hay que
        // avisarle explícitamente al dispositivo remoto (el Host) "sí
        // quiero que me mandes notificaciones de esto". Esto es un
        // paso extra que exige el protocolo Bluetooth mismo.
        let sub_status = credentials_char
            .WriteClientCharacteristicConfigurationDescriptorAsync(
                GattClientCharacteristicConfigurationDescriptorValue::Notify,
            )
            .map_err(|e| win_err_ctx(e, "WriteClientCharacteristicConfigurationDescriptorAsync"))?
            .get()
            .map_err(|e| win_err_ctx(e, "WriteClientCCCD.get()"))?;

        if sub_status != GattCommunicationStatus::Success {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("No se pudo activar notificaciones: {:?}", sub_status),
            ));
        }

        println!("[GATT-cliente] Conexión y suscripción listas.");
        Ok((Self { _device: device }, transport))
    }
}

/// ⚠️ NUNCA PROBADO EN VIVO — hace tres cosas en secuencia, cada una
/// bloqueando hasta terminar:
/// 1. El handshake Noise (usando el MISMO código que ya funciona
///    perfecto sobre TCP, solo que ahora corre sobre Bluetooth).
/// 2. Manda la oferta (nombre + tamaño del archivo), ya cifrada.
/// 3. Espera la respuesta del Host: o trae las credenciales del
///    hotspot (aceptó), o dice que rechazó.
pub fn negotiate(
    transport: BleClientTransport,
    file_name: &str,
    file_size: u64,
) -> io::Result<HotspotResponse> {
    println!("[GATT-cliente] Iniciando handshake Noise por BLE...");
    let mut channel = perform_handshake_initiator(transport)?;
    println!("[GATT-cliente] Handshake completo. Mandando oferta...");

    channel.send(&encode_metadata(file_name, file_size))?;

    println!("[GATT-cliente] Oferta enviada. Esperando respuesta del Host...");
    let response_bytes = channel.recv(4096)?;
    decode_response(&response_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "respuesta inválida del Host"))
}