#![cfg(target_os = "windows")]
#![allow(dead_code)]

use crate::ble_transport_windows::{encode_response, BleServerTransport, HotspotResponse};
use aircore_core::crypto::{perform_handshake_responder, SecureChannel};
use aircore_core::discovery::AIRCORE_SERVICE_UUID;
use aircore_core::transfer::decode_metadata;
use std::io;
use uuid::Uuid;
use windows::core::GUID;
use windows::Devices::Bluetooth::BluetoothError;
use windows::Devices::Bluetooth::GenericAttributeProfile::{
    GattCharacteristicProperties, GattLocalCharacteristic, GattLocalCharacteristicParameters,
    GattProtectionLevel, GattServiceProvider, GattServiceProviderAdvertisingParameters,
    GattWriteRequestedEventArgs,
};
use windows::Foundation::TypedEventHandler;
use windows::Storage::Streams::DataReader;
use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};

pub const OFFER_CHARACTERISTIC_UUID: Uuid =
    Uuid::from_u128(0x8a51ec22_8f74_4d2e_9e29_9f1e2b9d5c32);
pub const CREDENTIALS_CHARACTERISTIC_UUID: Uuid =
    Uuid::from_u128(0x8a51ec22_8f74_4d2e_9e29_9f1e2b9d5c33);

/// Convierte un UUID (representación estándar RFC 4122, big-endian) a
/// un GUID de Windows respetando el layout real de sus campos.
pub(crate) fn uuid_to_guid(u: Uuid) -> GUID {
    let b = u.as_bytes();
    let data1 = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    let data2 = u16::from_be_bytes([b[4], b[5]]);
    let data3 = u16::from_be_bytes([b[6], b[7]]);
    let data4: [u8; 8] = [b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]];
    GUID::from_values(data1, data2, data3, data4)
}

fn win_err_ctx(e: windows::core::Error, context: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Other,
        format!("Error de Windows GATT en [{}]: {:?}", context, e),
    )
}

pub struct WindowsGattServer {
    provider: GattServiceProvider,
}

impl WindowsGattServer {
    /// Arranca el servidor GATT y el anuncio conectable. Devuelve el
    /// servidor junto con un transporte Noise ya listo para negociar
    /// UNA oferta — llama a `accept_offer` para bloquear hasta que
    /// llegue y se autentique.
    pub fn start() -> io::Result<(Self, BleServerTransport)> {
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        }

        println!("[GATT] Creando GattServiceProvider...");
        let service_guid = uuid_to_guid(AIRCORE_SERVICE_UUID);
        let provider_result = GattServiceProvider::CreateAsync(service_guid)
            .map_err(|e| win_err_ctx(e, "GattServiceProvider::CreateAsync"))?
            .get()
            .map_err(|e| win_err_ctx(e, "CreateAsync.get()"))?;

        let error = provider_result
            .Error()
            .map_err(|e| win_err_ctx(e, "provider_result.Error()"))?;
        if error != BluetoothError::Success {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("No se pudo crear el GattServiceProvider: {:?}", error),
            ));
        }

        let provider = provider_result
            .ServiceProvider()
            .map_err(|e| win_err_ctx(e, "provider_result.ServiceProvider()"))?;
        let service = provider
            .Service()
            .map_err(|e| win_err_ctx(e, "provider.Service()"))?;

        println!("[GATT] Creando característica de oferta (escribible, canal entrante)...");
        let offer_params = GattLocalCharacteristicParameters::new()
            .map_err(|e| win_err_ctx(e, "GattLocalCharacteristicParameters::new (offer)"))?;
        offer_params
            .SetCharacteristicProperties(GattCharacteristicProperties::Write)
            .map_err(|e| win_err_ctx(e, "offer_params.SetCharacteristicProperties"))?;
        offer_params
            .SetWriteProtectionLevel(GattProtectionLevel::Plain)
            .map_err(|e| win_err_ctx(e, "offer_params.SetWriteProtectionLevel"))?;

        let offer_char_result = service
            .CreateCharacteristicAsync(uuid_to_guid(OFFER_CHARACTERISTIC_UUID), &offer_params)
            .map_err(|e| win_err_ctx(e, "CreateCharacteristicAsync (offer)"))?
            .get()
            .map_err(|e| win_err_ctx(e, "offer CreateCharacteristicAsync.get()"))?;
        let offer_char: GattLocalCharacteristic = offer_char_result
            .Characteristic()
            .map_err(|e| win_err_ctx(e, "offer_char_result.Characteristic()"))?;

        println!("[GATT] Creando característica de credenciales (notificable, canal saliente)...");
        let cred_params = GattLocalCharacteristicParameters::new()
            .map_err(|e| win_err_ctx(e, "GattLocalCharacteristicParameters::new (cred)"))?;
        cred_params
            .SetCharacteristicProperties(GattCharacteristicProperties::Notify)
            .map_err(|e| win_err_ctx(e, "cred_params.SetCharacteristicProperties"))?;

        let cred_char_result = service
            .CreateCharacteristicAsync(uuid_to_guid(CREDENTIALS_CHARACTERISTIC_UUID), &cred_params)
            .map_err(|e| win_err_ctx(e, "CreateCharacteristicAsync (cred)"))?
            .get()
            .map_err(|e| win_err_ctx(e, "cred CreateCharacteristicAsync.get()"))?;
        let credentials_char = cred_char_result
            .Characteristic()
            .map_err(|e| win_err_ctx(e, "cred_char_result.Characteristic()"))?;

        // El transporte Noise: manda por `credentials_char` (notify),
        // recibe los bytes que llegan por `offer_char` (write) a
        // través de este canal, alimentado por el handler de abajo.
        let (transport, tx) = BleServerTransport::new(credentials_char);

        let handler = TypedEventHandler::new(
            move |_sender, args: windows::core::Ref<'_, GattWriteRequestedEventArgs>| {
                if let Some(args) = args.as_ref() {
                    if let Ok(request_op) = args.GetRequestAsync() {
                        if let Ok(request) = request_op.get() {
                            if let Ok(value) = request.Value() {
                                if let Ok(reader) = DataReader::FromBuffer(&value) {
                                    let len = reader.UnconsumedBufferLength().unwrap_or(0) as usize;
                                    let mut bytes = vec![0u8; len];
                                    if reader.ReadBytes(&mut bytes).is_ok() {
                                        let _ = tx.send(bytes);
                                    }
                                }
                            }
                            let _ = request.Respond();
                        }
                    }
                }
                Ok(())
            },
        );
        offer_char
            .WriteRequested(&handler)
            .map_err(|e| win_err_ctx(e, "offer_char.WriteRequested"))?;

        println!("[GATT] Iniciando anuncio conectable...");
        let adv_params = GattServiceProviderAdvertisingParameters::new()
            .map_err(|e| win_err_ctx(e, "GattServiceProviderAdvertisingParameters::new"))?;
        adv_params
            .SetIsConnectable(true)
            .map_err(|e| win_err_ctx(e, "adv_params.SetIsConnectable"))?;
        adv_params
            .SetIsDiscoverable(true)
            .map_err(|e| win_err_ctx(e, "adv_params.SetIsDiscoverable"))?;

        provider
            .StartAdvertisingWithParameters(&adv_params)
            .map_err(|e| win_err_ctx(e, "provider.StartAdvertisingWithParameters"))?;

        println!("[GATT] Servidor GATT activo y anunciándose.");
        Ok((Self { provider }, transport))
    }

    pub fn stop(&self) -> io::Result<()> {
        self.provider
            .StopAdvertising()
            .map_err(|e| win_err_ctx(e, "provider.StopAdvertising"))?;
        Ok(())
    }
}

/// Bloquea hasta completar el handshake Noise y recibir la oferta.
/// Devuelve el canal cifrado (para responder después) junto con el
/// nombre y tamaño del archivo ofrecido.
pub fn accept_offer(
    transport: BleServerTransport,
) -> io::Result<(SecureChannel<BleServerTransport>, String, u64)> {
    println!("[GATT] Esperando handshake Noise por BLE...");
    let mut channel = perform_handshake_responder(transport)?;
    println!("[GATT] Handshake completo. Esperando oferta...");

    let meta = channel.recv(4096)?;
    let (name, size) =
        decode_metadata(&meta).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "oferta inválida"))?;

    println!("[GATT] Oferta recibida: '{}' ({} bytes)", name, size);
    Ok((channel, name, size))
}

/// Manda la respuesta (aceptación con credenciales, o rechazo) por el
/// mismo canal cifrado.
pub fn respond(channel: &mut SecureChannel<BleServerTransport>, response: HotspotResponse) -> io::Result<()> {
    channel.send(&encode_response(&response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    #[ignore] // cargo test -p aircore-desktop -- --ignored --nocapture gatt_server_seguro
    fn arranca_servidor_gatt_seguro_y_espera_oferta() {
        let (server, transport) = WindowsGattServer::start().expect("el servidor debería arrancar");

        println!("[GATT] Esperando una oferta real por hasta 30 segundos (usa el cliente en otra máquina)...");
        let handle = thread::spawn(move || accept_offer(transport));

        match handle.join() {
            Ok(Ok((_, name, size))) => println!("[GATT] ¡Oferta recibida y autenticada! '{}' ({} bytes)", name, size),
            Ok(Err(e)) => println!("[GATT] No se completó la negociación (esperado si no hay cliente real): {}", e),
            Err(_) => println!("[GATT] El hilo de negociación entró en panic."),
        }

        server.stop().ok();
    }
}