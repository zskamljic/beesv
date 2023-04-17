use yew::platform::spawn_local;
use yew::prelude::*;
use yew_hooks::use_interval;

use crate::bip32::DerivePath;
use crate::bip32::XPrv;
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
    let syncing = use_state(|| true);
    let balance = use_state(|| 0);

    {
        let derived_key = xprv.derive_path("m/0'").expect("Should derive key");
        let public = derived_key
            .derive_public()
            .expect("Should create public key");

        let loader = syncing.clone();
        let balance = balance.clone();
        use_interval(
            move || {
                let public = public.clone();
                if !*loader.clone() {
                    loader.set(true);

                    let mut rate_limiter = RateLimiter::new(3);
                    let balance = balance.clone();
                    let loader = loader.clone();
                    spawn_local(async move {
                        let result = transactions::fetch_for_address(&public, &mut rate_limiter)
                            .await
                            .unwrap();
                        balance.set(result.balance);
                        loader.set(false);
                    });
                }
            },
            5000,
        );
    };

    html! {
        <>
            <header><h1>{"Welcome to BeeSV"}</h1></header>
            if *syncing {
                <p>{"Syncing"}</p>
            } else {
                <p>{"Done syncing"}</p>
            }
            <p>{"Balance: "}{*balance as f32 / 100_000_000f32}{"₿"}</p>
        </>
    }
}
