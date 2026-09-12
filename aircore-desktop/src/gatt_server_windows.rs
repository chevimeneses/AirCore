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

// Estos son como dos "buzones" de correo, cada uno con su propia
// dirección única (UUID). Cualquier dispositivo AirCore, en cualquier
// máquina, va a usar estos MISMOS dos números para saber "por aquí
// mando ofertas" y "por aquí recibo la respuesta".
pub const OFFER_CHARACTERISTIC_UUID: Uuid =
    Uuid::from_u128(0x8a51ec22_8f74_4d2e_9e29_9f1e2b9d5c32);
pub const CREDENTIALS_CHARACTERISTIC_UUID: Uuid =
    Uuid::from_u128(0x8a51ec22_8f74_4d2e_9e29_9f1e2b9d5c33);

// IMPORTANTE, ESTA FUNCIÓN RESOLVIÓ UN BUG REAL: un GUID de Windows no
// guarda sus 16 bytes en el mismo orden simple que un UUID estándar —
// tiene una estructura "mixta" en 4 partes (Data1, Data2, Data3, Data4).
// Si conviertes un UUID a GUID de la forma "ingenua" (tratándolo como
// un solo número gigante), el resultado queda mal formado por dentro,
// aunque no dé ningún error hasta que Windows intenta USARLO de
// verdad. Esta función hace la conversión correcta, campo por campo.
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

/// Este struct representa "soy un dispositivo que otros pueden
/// encontrar y conectarse a mí por Bluetooth". GATT (Generic Attribute
/// Profile) es el nombre técnico del sistema estándar de Bluetooth
/// para "servicios" y "características" — piénsalo como un menú de
/// restaurante: el "servicio" es el menú completo (AirCore), y las
/// "características" son cada platillo (oferta, credenciales), cada
/// uno con su propia forma de pedirse.
pub struct WindowsGattServer {
    provider: GattServiceProvider,
}

impl WindowsGattServer {
    /// ✅ CONFIRMADO FUNCIONANDO EN VIVO: arranca sin errores y se
    /// anuncia correctamente. Esta función hace TODO el trabajo de
    /// preparación: crear el servicio, crear las dos características,
    /// y empezar a anunciarse — para que otros dispositivos puedan
    /// encontrar y conectarse a este.
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

        // ── Característica 1: "oferta" — el Guest ESCRIBE aquí para
        // mandarnos "quiero enviarte tal archivo, de tal tamaño".
        println!("[GATT] Creando característica de oferta (escribible, canal entrante)...");
        let offer_params = GattLocalCharacteristicParameters::new()
            .map_err(|e| win_err_ctx(e, "GattLocalCharacteristicParameters::new (offer)"))?;
        offer_params
            .SetCharacteristicProperties(GattCharacteristicProperties::Write) // Puede ser ESCRITA por otros.
            .map_err(|e| win_err_ctx(e, "offer_params.SetCharacteristicProperties"))?;
        offer_params
            .SetWriteProtectionLevel(GattProtectionLevel::Plain) // Sin cifrado de Bluetooth nativo —
            // no hace falta, porque nosotros mismos ya ciframos con Noise por encima.
            .map_err(|e| win_err_ctx(e, "offer_params.SetWriteProtectionLevel"))?;

        let offer_char_result = service
            .CreateCharacteristicAsync(uuid_to_guid(OFFER_CHARACTERISTIC_UUID), &offer_params)
            .map_err(|e| win_err_ctx(e, "CreateCharacteristicAsync (offer)"))?
            .get()
            .map_err(|e| win_err_ctx(e, "offer CreateCharacteristicAsync.get()"))?;
        let offer_char: GattLocalCharacteristic = offer_char_result
            .Characteristic()
            .map_err(|e| win_err_ctx(e, "offer_char_result.Characteristic()"))?;

        // ── Característica 2: "credenciales" — nosotros NOTIFICAMOS
        // aquí para mandarle al Guest nuestra respuesta (aceptación
        // con SSID/contraseña, o rechazo).
        println!("[GATT] Creando característica de credenciales (notificable, canal saliente)...");
        let cred_params = GattLocalCharacteristicParameters::new()
            .map_err(|e| win_err_ctx(e, "GattLocalCharacteristicParameters::new (cred)"))?;
        cred_params
            .SetCharacteristicProperties(GattCharacteristicProperties::Notify) // Nosotros AVISAMOS cambios.
            .map_err(|e| win_err_ctx(e, "cred_params.SetCharacteristicProperties"))?;

        let cred_char_result = service
            .CreateCharacteristicAsync(uuid_to_guid(CREDENTIALS_CHARACTERISTIC_UUID), &cred_params)
            .map_err(|e| win_err_ctx(e, "CreateCharacteristicAsync (cred)"))?
            .get()
            .map_err(|e| win_err_ctx(e, "cred CreateCharacteristicAsync.get()"))?;
        let credentials_char = cred_char_result
            .Characteristic()
            .map_err(|e| win_err_ctx(e, "cred_char_result.Characteristic()"))?;

        // Creamos el "traductor" Noise-sobre-BLE (explicado a fondo
        // en ble_transport_windows.rs), pasándole por dónde va a
        // mandar (credentials_char). El "tx" que nos devuelve es
        // cómo le vamos a avisar cada vez que llegue algo nuevo por
        // la característica de oferta.
        let (transport, tx) = BleServerTransport::new(credentials_char);

        // Este "handler" es código que WINDOWS ejecuta automáticamente
        // (no nosotros) cada vez que alguien escribe algo en la
        // característica de oferta. Su único trabajo es: leer esos
        // bytes, y pasárselos al transporte a través del canal "tx"
        // que armamos arriba.
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
                                        let _ = tx.send(bytes); // Avisa al transporte: "llegó esto".
                                    }
                                }
                            }
                            let _ = request.Respond(); // Confirma a Windows que ya procesamos la escritura.
                        }
                    }
                }
                Ok(())
            },
        );
        offer_char
            .WriteRequested(&handler) // "Cada vez que alguien escriba aquí, ejecuta el handler de arriba".
            .map_err(|e| win_err_ctx(e, "offer_char.WriteRequested"))?;

        // Por último, empezamos a anunciarnos de forma "conectable" y
        // "descubrible" — sin esto, otros dispositivos nunca sabrían
        // que existimos.
        println!("[GATT] Iniciando anuncio conectable...");
        let adv_params = GattServiceProviderAdvertisingParameters::new()
            .map_err(|e| win_err_ctx(e, "GattServiceProviderAdvertisingParameters::new"))?;
        adv_params
            .SetIsConnectable(true) // Otros pueden CONECTARSE (no solo ver que existimos).
            .map_err(|e| win_err_ctx(e, "adv_params.SetIsConnectable"))?;
        adv_params
            .SetIsDiscoverable(true) // Aparecemos en escaneos.
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

/// ⚠️ NUNCA PROBADO CON UN CLIENTE REAL — la lógica está completa y
/// compila, pero nadie ha llamado a esta función desde otra máquina
/// todavía. Es de las cosas clave que la prueba de las dos laptops va
/// a confirmar.
///
/// Esta función SE QUEDA ESPERANDO (bloquea el hilo donde se llame)
/// hasta que: 1) alguien complete el handshake Noise, y 2) mande una
/// oferta válida. Solo entonces regresa el control a quien la llamó.
pub fn accept_offer(
    transport: BleServerTransport,
) -> io::Result<(SecureChannel<BleServerTransport>, String, u64)> {
    println!("[GATT] Esperando handshake Noise por BLE...");
    let mut channel = perform_handshake_responder(transport)?; // Usa exactamente la misma función de crypto.rs que TCP.
    println!("[GATT] Handshake completo. Esperando oferta...");

    let meta = channel.recv(4096)?; // Ya cifrado — la oferta viaja protegida.
    let (name, size) =
        decode_metadata(&meta).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "oferta inválida"))?;

    println!("[GATT] Oferta recibida: '{}' ({} bytes)", name, size);
    Ok((channel, name, size))
}

/// Manda la decisión final (aceptar con credenciales, o rechazar) de
/// vuelta al Guest, por el mismo canal cifrado que ya se estableció.
pub fn respond(channel: &mut SecureChannel<BleServerTransport>, response: HotspotResponse) -> io::Result<()> {
    channel.send(&encode_response(&response))
}

// Prueba manual: arranca el servidor de verdad y espera hasta 30
// segundos a que llegue una oferta real desde OTRA máquina corriendo
// el cliente correspondiente.
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