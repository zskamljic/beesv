use yew::platform::spawn_local;
use yew::prelude::*;
use yew_hooks::use_interval;

use crate::bip32::DerivePath;
use crate::bip32::XPrv;
use crate::bip32::XPub;
use crate::ratelimit::RateLimiter;
use crate::recover::open_settings;
use crate::transactions;
use crate::util::log;

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
    let syncing = use_state(|| false);
    let balance = use_state(|| 0);

    let derived_key = xprv.derive_path("m/0'").expect("Should derive key");
    let public = derived_key
        .derive_public()
        .expect("Should create public key");

    let loader = syncing.clone();
    let balance_state = balance.clone();
    use_interval(
        move || trigger_sync(public.clone(), loader.clone(), balance_state.clone()),
        5000,
    );

    html! {
        <>
            <header><h1>{"Welcome to BeeSV"}</h1></header>
            <p>{"Balance: "}{*balance as f32 / 100_000_000f32}{"₿"}</p>
            if *syncing {
                <p>{"Syncing..."}</p>
            }
        </>
    }
}

fn trigger_sync(xpub: XPub, loader: UseStateHandle<bool>, balance: UseStateHandle<u64>) {
    if *loader {
        return;
    }

    loader.set(true);

    let mut rate_limiter = RateLimiter::new(3);
    spawn_local(async move {
        let result = transactions::fetch_for_address(&xpub, &mut rate_limiter)
            .await
            .unwrap();
        balance.set(result.balance);
        loader.set(false);
    });
}
