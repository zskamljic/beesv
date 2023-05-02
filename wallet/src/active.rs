use gloo_dialogs::alert;
use web_sys::HtmlInputElement;
use yew::platform::spawn_local;
use yew::prelude::*;
use yew_hooks::use_interval;

use crate::bip32::DerivePath;
use crate::bip32::XPrv;
use crate::bip32::XPub;
use crate::ratelimit::RateLimiter;
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
            <p>{"Balance: "}{format!("{:.08}", *balance as f32 / 100_000_000f32)}{"₿"}</p>
            if *syncing {
                <p>{"Syncing..."}</p>
            } else {
                <p>{"Synced"}</p>
            }
            <p>{"Send BSV"}</p>
            <SendToAddress />
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

#[function_component(SendToAddress)]
fn send_to_address() -> Html {
    let address = use_state(|| String::default());
    let amount = use_state(|| 0f32);

    let set_address = {
        let address = address.clone();
        move |e: InputEvent| {
            let input: HtmlInputElement = e.target_unchecked_into();
            address.set(input.value());
        }
    };

    let set_amount = {
        let amount = amount.clone();
        move |e: InputEvent| {
            let input: HtmlInputElement = e.target_unchecked_into();
            let value = input.value().parse().unwrap_or(0f32);
            amount.set(value);
        }
    };

    let send_transaction = {
        move |_| {
            if address.is_empty() {
                alert("Address was not present");
                return;
            }
            if *amount < 0.000_000_01f32 {
                alert("Must send a small value");
                return;
            }
        }
    };

    html! {
        <>
            <label for="address">{"Address:"}</label>
            <input id="address" oninput={set_address}/>
            <label for="amount">{"Amount to send:"}</label>
            <input id="amount" type="number" oninput={set_amount}/>
            <button onclick={send_transaction}>{"Send"}</button>
        </>
    }
}
