use yew::platform::spawn_local;
use yew::prelude::*;

use crate::bip32::DerivePath;
use crate::bip32::XPrv;
use crate::recover::open_settings;
use crate::transactions;

#[function_component(Popup)]
pub fn popup() -> Html {
    let open_settings = { move |_| open_settings() };

    html! {
        <>
            <header><h1>{"Welcome to BeeSV"}</h1></header>
            <div onclick={open_settings}>{"Balance"}</div>
        </>
    }
}

#[derive(Properties, PartialEq)]
pub struct FullscreenProps {
    pub xprv: XPrv,
}

#[function_component(Fullscreen)]
pub fn fullscreen(FullscreenProps { xprv }: &FullscreenProps) -> Html {
    let syncing = use_state(|| true);

    let derived_key = xprv.derive_path("m/0'/0").expect("Should derive key");
    let public = derived_key
        .derive_public()
        .expect("Should create public key");

    let inner_loader = syncing.clone();
    if *syncing {
        spawn_local(async move {
            transactions::fetch_for_address(&public).await.unwrap();
            inner_loader.set(false);
        });
    }

    html! {
        <>
            <header><h1>{"Welcome to BeeSV"}</h1></header>
            {*syncing}
            if *syncing {
                <p>{"Syncing"}</p>
            } else {
                <p>{"Done syncing"}</p>
            }
        </>
    }
}
