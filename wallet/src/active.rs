use yew::platform::spawn_local;
use yew::prelude::*;

use crate::bip32::DerivePath;
use crate::bip32::XPrv;
use crate::transactions;

#[function_component(Popup)]
pub fn popup() -> Html {
    html! {
        <>
            <header><h1>{"Welcome to BeeSV"}</h1></header>
            <div>{"Balance"}</div>
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

    let addresses: Vec<_> = (0..400)
        .map(|i| {
            public
                .derive(i)
                .expect("Derivation of public key should succeed")
                .to_address()
        })
        .collect();

    spawn_local(async move {
        transactions::fetch_for_address(&addresses).await.unwrap();
    });

    html! {
        <>
            <header><h1>{"Welcome to BeeSV"}</h1></header>
            {"Welcome!"}
        </>
    }
}
