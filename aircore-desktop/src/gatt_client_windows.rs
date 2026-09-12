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

pub struct WindowsGattClient {
    _device: BluetoothLEDevice, // se mantiene viva mientras dure la conexión
}

impl WindowsGattClient {
    /// Se conecta al dispositivo AirCore en la dirección Bluetooth dada
    /// (formato u64, tal como lo entrega WindowsBleScanner), y devuelve
    /// un transporte Noise listo para negociar.
    pub fn connect(bluetooth_address: u64) -> io::Result<(Self, BleClientTransport)> {
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        }

        println!("[GATT-cliente] Conectando a dirección {:#014x}...", bluetooth_address);
        let device = BluetoothLEDevice::FromBluetoothAddressAsync(bluetooth_address)
            .map_err(|e| win_err_ctx(e, "BluetoothLEDevice::FromBluetoothAddressAsync"))?
            .get()
            .map_err(|e| win_err_ctx(e, "FromBluetoothAddressAsync.get()"))?;

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
            .GetAt(0)
            .map_err(|e| win_err_ctx(e, "services.GetAt(0) — ¿el Host está anunciando?"))?;

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

        // El transporte Noise: manda por `offer_char` (write), recibe
        // los bytes que lleguen por `credentials_char` (notify) a
        // través del canal, alimentado por el handler de abajo.
        let (transport, tx) = BleClientTransport::new(offer_char);

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
            .ValueChanged(&handler)
            .map_err(|e| win_err_ctx(e, "credentials_char.ValueChanged"))?;

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

/// Realiza el handshake Noise, manda la oferta, y bloquea hasta
/// recibir la respuesta del Host (aceptación con credenciales, o
/// rechazo).
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