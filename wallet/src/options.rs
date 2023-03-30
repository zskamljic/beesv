use wasm_bindgen::prelude::*;
use web_sys::{Event, HtmlInputElement};
use yew::prelude::*;

use crate::{bip39::Seed, util::log};

const WORDS: &str = include_str!("english.txt");

#[function_component(Options)]
pub fn options() -> Html {
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
        move |_| {
            let seed = Seed::generate(&mnemonic_words.join(" "), "");
            let xprv: String = seed
                .to_xprv()
                .and_then(|k| k.serialize())
                .expect("Key should be formatted");
            log(&xprv);
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
