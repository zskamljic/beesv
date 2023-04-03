use wasm_bindgen::prelude::*;

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
