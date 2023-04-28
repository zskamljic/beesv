use crate::bip32::XPrv;
use std::str::FromStr;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use web_sys::window;
use yew::prelude::*;
use yew::{function_component, Renderer};

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

mod active;
mod bip32;
mod bip39;
mod ratelimit;
mod recover;
mod script;
mod sending;
mod transactions;
mod util;

#[wasm_bindgen(start)]
pub fn main() {
    Renderer::<App>::new().render();
}

#[function_component(App)]
fn app() -> Html {
    let page = window().unwrap_throw().document().unwrap_throw().title();
    let page = page.as_str();

    let xprv = use_state(|| None);
    spawn_local(load_xprv(xprv.clone()));
    let xprv_recover = xprv.clone();
    let on_recover = {
        move |_| {
            let xprv = xprv_recover.clone();
            spawn_local(load_xprv(xprv));
        }
    };

    match (page, xprv.as_ref()) {
        ("BeeSV Settings", None) => html! {<recover::Recover {on_recover} />},
        ("BeeSV Settings", Some(xprv)) => html! {<active::Fullscreen xprv={xprv.clone()}/>},
        (_, None) => html! {<recover::Popup />},
        (_, Some(_xprv)) => html! {<active::Popup/>},
    }
}

async fn load_xprv(xprv_state: UseStateHandle<Option<XPrv>>) {
    match util::store_load::<String>("xprv").await {
        Ok(Some(value)) => {
            let Ok(xprv) = XPrv::from_str(&value) else {
                return;
            };
            xprv_state.set(Some(xprv));
        }
        Err(error) => {
            gloo_dialogs::alert(&format!("Unable to load wallet: {error:?}"));
        }
        _ => (), // Wallet not stored
    };
}
