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
pub fn main() {
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
