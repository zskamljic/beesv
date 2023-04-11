use util::log;
use wasm_bindgen::prelude::*;
use web_sys::window;
use yew::Renderer;

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

mod bip32;
mod bip39;
mod options;
mod popup;
mod transactions;
mod util;

#[wasm_bindgen(start)]
pub async fn main() {
    let wallet: Option<String> = util::store_load("test").await.unwrap();
    match wallet {
        Some(value) => log(&value),
        None => log("Wallet not stored"),
    }
    util::store_save("test", "test").await.unwrap();

    let callback =
        Closure::wrap(Box::new(move |v| log(&format!("value: {v:?}"))) as Box<dyn FnMut(JsValue)>);
    util::storage_get2(&JsValue::null(), callback.as_ref().unchecked_ref());
    callback.forget();

    match window()
        .unwrap_throw()
        .document()
        .unwrap_throw()
        .title()
        .as_str()
    {
        "BeeSV Settings" => {
            Renderer::<options::Options>::new().render();
        }
        _ => {
            Renderer::<popup::Popup>::new().render();
        }
    };
}
