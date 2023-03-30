use std::error::Error;

use wasm_bindgen::prelude::*;

pub type JsResult<T> = Result<T, JsValue>;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(message: &str);
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

pub fn map_any_err<T: Error>(error: T) -> JsValue {
    JsValue::from_str(&format!("{error:?}"))
}
