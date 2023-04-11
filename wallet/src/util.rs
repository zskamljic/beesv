use anyhow::Result;
use serde::{de::DeserializeOwned, Serialize};
use serde_wasm_bindgen::to_value;
use std::collections::HashMap;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(message: &str);

    #[wasm_bindgen(catch, js_namespace = ["chrome", "storage", "local"], js_name = set)]
    async fn storage_set(data: &JsValue) -> Result<(), JsValue>;

    #[wasm_bindgen(catch, js_namespace = ["chrome", "storage", "local"], js_name = get)]
    async fn storage_get(data: &JsValue) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(js_namespace = ["chrome", "storage", "local"], js_name = get)]
    pub fn storage_get2(data: &JsValue, callback: &js_sys::Function);
}

#[derive(Debug, Error)]
enum JsError {
    #[error("Unable to convert to JsValue")]
    UnableToConvert,
    #[error("Unable to convert promise")]
    PromiseError,
}

pub async fn store_save<T>(key: &str, value: &T) -> Result<()>
where
    T: Serialize + ?Sized,
{
    let mut storage = HashMap::new();
    storage.insert(key, value);
    let Ok(data) = to_value(&storage) else {
        return Err(JsError::UnableToConvert.into());
    };

    let Ok(_) = storage_set(&data).await else {
        return Err(JsError::PromiseError.into())
    };
    Ok(())
}

pub async fn store_load<T>(key: &str) -> Result<Option<T>>
where
    T: DeserializeOwned,
{
    let Ok(data) = to_value(&vec![key]) else {
        return Err(JsError::UnableToConvert.into());
    };
    let Ok(result) = storage_get(&data).await else {
        return Err(JsError::PromiseError.into())
    };
    let result: Option<String> = result.as_string();
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
