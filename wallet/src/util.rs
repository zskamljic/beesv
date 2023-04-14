use anyhow::Result;
use js_sys::{Object, Reflect};
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;
use wasm_bindgen::prelude::*;
use web_sys::window;

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
