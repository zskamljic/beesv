use gloo_dialogs::alert;
use wasm_bindgen::prelude::*;
use web_sys::{Event, HtmlInputElement};
use yew::{platform::spawn_local, prelude::*};

use crate::{
    bip39::Seed,
    util::{self, log},
};

const WORDS: &str = include_str!("english.txt");

#[derive(Properties, PartialEq)]
pub struct RecoverProps {
    pub on_recover: Callback<()>,
}

#[function_component(Recover)]
pub fn recover(RecoverProps { on_recover }: &RecoverProps) -> Html {
    let mnemonic_words = use_state(|| vec![String::default(); 12]);
    let word_changed = {
        let mnemonic_words = mnemonic_words.clone();
        move |(index, word)| {
            let mut value: Vec<_> = mnemonic_words.iter().cloned().collect();
            value[index as usize] = word;
            mnemonic_words.set(value);
        }
    };

    let recover_clicked = {
        let on_recover = on_recover.clone();
        move |_| {
            let on_recover = on_recover.clone();
            let seed = Seed::generate(&mnemonic_words.join(" "), "");
            let xprv = seed.to_xprv().expect("Should create a private key");
            spawn_local(async move {
                let serialized = String::from(&xprv);
                let Err(error) = util::store_save("xprv", &serialized).await else {
                    on_recover.emit(());
                    return;
                };
                alert(&format!("Unable to save wallet: {error:?}"));
            });
        }
    };

    html! {
        <>
            <h1>{"Options"}</h1>
            <MnemonicInput word_changed={word_changed}/>
            <MnemonicDatalist/>
            <button onclick={recover_clicked}>{"Recover"}</button>
        </>
    }
}

#[derive(Properties, PartialEq)]
struct MnemonicInputProps {
    word_changed: Callback<(u32, String)>,
}

#[function_component(MnemonicInput)]
fn mnemonic_input(MnemonicInputProps { word_changed }: &MnemonicInputProps) -> Html {
    let rows: Vec<_> = (0..4)
        .map(|row| {
            html! {
                <MnemonicRow number={row} word_changed={word_changed.clone()} />
            }
        })
        .collect();

    html! {
        <div class="table">
            { rows }
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct RowProps {
    number: u32,
    word_changed: Callback<(u32, String)>,
}

#[function_component(MnemonicRow)]
fn mnemonic_row(
    RowProps {
        number,
        word_changed,
    }: &RowProps,
) -> Html {
    let columns: Vec<_> = (0..3)
        .map(|column| {
            let index = number * 3 + column;
            html! {
                <MnemonicCell index={index} word_changed={word_changed.clone()}/>
            }
        })
        .collect();

    html! {
        <div class="row">
            {columns}
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct CellProps {
    index: u32,
    word_changed: Callback<(u32, String)>,
}

#[function_component(MnemonicCell)]
fn mnemonic_cell(
    CellProps {
        index,
        word_changed,
    }: &CellProps,
) -> Html {
    let id = format!("word{index}");
    let placeholder = format!("Word {}", index + 1);

    let index = *index;
    let word_changed = word_changed.clone();
    let on_input = {
        move |e: InputEvent| {
            let target = e.target();
            let input = target.and_then(|t| t.dyn_into::<HtmlInputElement>().ok());

            if let Some(input) = input {
                input.set_custom_validity("");
                word_changed.emit((index, input.value()))
            }
        }
    };

    let on_change = {
        move |e: Event| {
            let target = e.target();
            let input = target.and_then(|t| t.dyn_into::<HtmlInputElement>().ok());

            if let Some(input) = input {
                check_word(&input);
            }
        }
    };

    html! {
        <div class="cell">
            <input id={id} oninput={on_input.clone()} onchange={on_change} type="text" list="word_list" placeholder={placeholder}/>
        </div>
    }
}

#[function_component(MnemonicDatalist)]
fn mnemonic_datalist() -> Html {
    let words: Vec<_> = WORDS
        .lines()
        .map(|word| {
            html! {
                <option>{ word }</option>
            }
        })
        .collect();

    html! {
        <datalist id="word_list">
            { words }
        </datalist>
    }
}

fn check_word(input: &HtmlInputElement) {
    let input_word = input.value();
    if !WORDS.contains(&input_word.to_lowercase()) {
        log("Showing error");
        input.set_custom_validity("Unrecognized word");
        input.report_validity();
    }
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["chrome", "runtime"], js_name = openOptionsPage)]
    fn open_settings();
}

#[function_component(Popup)]
pub fn popup() -> Html {
    let open_settings = { move |_| open_settings() };

    html! {
        <>
            <header><h1>{"Welcome to BeeSV"}</h1></header>
            <div class="container">
                <div class="vertical-center">
                    <button id="recover" onclick={open_settings}>{"Click here to recover wallet"}</button>
                </div>
            </div>
        </>
    }
}
