use anyhow::Result;
use js_sys::{Object, Reflect};
use ripemd::Ripemd160;
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use wasm_bindgen::prelude::*;
use web_sys::window;

pub const SATOSHIS_PER_BSV: u64 = 100_000_000;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(message: &str);

    #[wasm_bindgen(catch, js_namespace = ["chrome", "storage", "local"], js_name = set)]
    async fn storage_set(data: &JsValue) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch, js_namespace = ["chrome", "storage", "local"], js_name = get)]
    async fn storage_get(data: &JsValue) -> Result<JsValue, JsValue>;
}

#[derive(Debug, Error)]
enum JsError {
    #[error("An error occurred: {0}")]
    JsError(String),
}

impl From<JsValue> for JsError {
    fn from(value: JsValue) -> Self {
        Self::JsError(format!("{value:?}"))
    }
}

pub async fn store_save<T>(key: &str, value: &T) -> Result<()>
where
    T: Serialize + ?Sized,
{
    let object = Object::new();
    Reflect::set(
        &object,
        &JsValue::from_str(key),
        &JsValue::from_str(&serde_json::to_string(value)?),
    )
    .map_err(JsError::from)?;

    match storage_set(&object).await {
        Ok(_) => Ok(()),
        Err(error) => Err(JsError::from(error).into()),
    }
}

pub async fn store_load<T>(key: &str) -> Result<Option<T>>
where
    T: DeserializeOwned,
{
    let result = storage_get(&JsValue::from_str(key))
        .await
        .map_err(JsError::from)?;
    let result = Reflect::get(&result, &JsValue::from_str(key))
        .ok()
        .and_then(|v| v.as_string());
    Ok(match result {
        Some(value) => Some(serde_json::from_str::<T>(&value)?),
        None => None,
    })
}

trait OrError<T> {
    fn context(self, message: &str) -> Result<T, JsValue>;
}

impl<T> OrError<T> for Option<T> {
    fn context(self, message: &str) -> Result<T, JsValue> {
        match self {
            Some(value) => Ok(value),
            None => Err(JsValue::from_str(message)),
        }
    }
}

pub fn get_timestamp() -> f64 {
    let window = window().expect("Unable to get window object");
    let performance = window
        .performance()
        .expect("Unable to get performance object");

    performance.now()
}

pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(data);
    hash.finalize().into()
}

pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut ripemd = Ripemd160::new();
    ripemd.update(data);
    ripemd.finalize().try_into().expect("Should always succeed")
}

#[derive(Debug, Error)]
enum AddressError {
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    #[error("Address checksum error")]
    ChecksumError,
}

pub fn address_bytes(address: &str) -> Result<[u8; 20]> {
    let decoded_address = bs58::decode(address).into_vec()?;
    if decoded_address.len() != 25 || decoded_address[0] != 0 {
        return Err(AddressError::InvalidAddress(address.to_owned()).into());
    }

    let address: [u8; 20] = decoded_address[1..21]
        .try_into()
        .expect("Manual bounds set");
    let checksum = double_sha256(&decoded_address[..21]);
    if checksum[0..4] != decoded_address[21..] {
        return Err(AddressError::ChecksumError.into());
    }
    Ok(address)
}

pub fn to_address(bytes: [u8; 20]) -> String {
    let mut prefixed = Vec::with_capacity(21);
    prefixed.push(0x00);
    prefixed.extend(&bytes);

    let checksum = sha256(&sha256(&prefixed));
    prefixed.extend(&checksum[..4]);

    bs58::encode(prefixed).into_string()
}
