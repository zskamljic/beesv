use std::collections::HashMap;

use gloo_dialogs::alert;
use secp256k1::PublicKey;
use secp256k1::SecretKey;
use web_sys::HtmlInputElement;
use yew::platform::spawn_local;
use yew::prelude::*;
use yew_hooks::use_interval;

use crate::bip32::DerivePath;
use crate::bip32::XPrv;
use crate::ratelimit::RateLimiter;
use crate::recover::open_settings;
use crate::sending::Input;
use crate::sending::Output;
use crate::sending::Transaction;
use crate::transactions;
use crate::transactions::RichOutput;
use crate::transactions::WalletState;
use crate::util::log;
use crate::util::SATOSHIS_PER_BSV;

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
    let state = use_state(WalletState::default);

    let derived_key = xprv.derive_path("m/0'").expect("Should derive key");

    let loader = syncing.clone();
    let mutable_state = state.clone();
    use_interval(
        move || trigger_sync(derived_key.clone(), loader.clone(), mutable_state.clone()),
        5000,
    );

    html! {
        <>
            <header><h1>{"Welcome to BeeSV"}</h1></header>
            <p>{"Balance: "}{format!("{:.08}", state.balance as f32 / SATOSHIS_PER_BSV as f32)}{"₿"}</p>
            if *syncing {
                <p>{"Syncing..."}</p>
            } else {
                <p>{"Synced"}</p>
            }
            <p>{"Send BSV"}</p>
            <SendToAddress outputs={state.unspent_outputs.to_vec()} change_address={state.change_address()} key_fetcher={state.address_keys()} />
        </>
    }
}

fn trigger_sync(xprv: XPrv, loader: UseStateHandle<bool>, state: UseStateHandle<WalletState>) {
    if *loader {
        return;
    }

    loader.set(true);

    let mut rate_limiter = RateLimiter::new(3);
    spawn_local(async move {
        let result = transactions::fetch_for_address(&xprv, &mut rate_limiter)
            .await
            .unwrap();
        state.set(result);
        loader.set(false);
    });
}

#[derive(Properties, PartialEq)]
struct SendToAddressProps {
    outputs: Vec<RichOutput>,
    change_address: String,
    key_fetcher: HashMap<[u8; 20], (SecretKey, PublicKey)>,
}

#[function_component(SendToAddress)]
fn send_to_address(
    SendToAddressProps {
        outputs,
        change_address,
        key_fetcher,
    }: &SendToAddressProps,
) -> Html {
    let address = use_state(String::default);
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
        let outputs = outputs.clone();
        let change_address = change_address.clone();
        let key_fetcher = key_fetcher.clone();
        move |_| {
            if address.is_empty() {
                alert("Address was not present");
                return;
            }
            if *amount < 0.000_000_01f32 {
                alert("Must send a small value");
                return;
            }
            let amount = (*amount * SATOSHIS_PER_BSV as f32) as u64;
            let mut transaction = Transaction::default();
            let output = match Output::new(amount, &address) {
                Ok(output) => output,
                Err(error) => {
                    alert(&format!("Can't send: {error:?}"));
                    return;
                }
            };
            transaction.add_output(output);

            let output_map = outputs
                .iter()
                .cloned()
                .map(|o| {
                    (
                        (hex::decode(o.tx_hash).unwrap(), o.tx_pos),
                        Output::new_from_decoded(o.amount, o.address),
                    )
                })
                .collect();
            let mut outputs = outputs.clone();
            let mut output_sum = 0;
            while output_sum < amount && !outputs.is_empty() {
                let output = outputs.remove(0);
                output_sum += output.amount;
                transaction.add_input(
                    Input::new(output.tx_hash, output.tx_pos)
                        .expect("Input tx hash should be decodable"),
                );
            }
            if amount > output_sum {
                alert(&format!(
                    "Unable to send, insufficient balance, missing {}",
                    amount - output_sum
                ));
                return;
            }
            let mut fee = transaction.suggested_fee();
            while output_sum - amount < fee && !outputs.is_empty() {
                let output = outputs.remove(0);
                output_sum += output.amount;
                transaction.add_input(
                    Input::new(output.tx_hash, output.tx_pos)
                        .expect("Input tx hash should be decodable"),
                );
                fee = transaction.suggested_fee();
            }
            if output_sum - amount < fee {
                alert(&format!(
                    "Unable to send transaction, insufficient BSV for transaction+fee: {}",
                    amount + fee
                ));
                return;
            }
            let change = output_sum - amount - fee;
            let change = match Output::new(change, &change_address) {
                Ok(change) => change,
                Err(error) => {
                    alert(&format!(
                        "Unable to send transaction, invalid change address: {error:?}"
                    ));
                    return;
                }
            };
            transaction.add_output(change);
            if let Err(error) = transaction.sign_inputs(&output_map, &key_fetcher) {
                alert(&format!("Unable to sign transaction: {error:?}"));
                return;
            }

            log(&format!(
                "Transaction: {}, fee: {}",
                hex::encode(Vec::from(&transaction)),
                transaction.suggested_fee()
            ));
            spawn_local(async move {
                if let Err(error) = transactions::publish_transaction(&transaction).await {
                    alert(&format!("Unable to publish transaction: {error:?}"));
                }
            })
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
