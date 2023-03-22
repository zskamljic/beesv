use wasm_bindgen::prelude::*;
use web_sys::{Event, HtmlInputElement};
use yew::prelude::*;

use crate::util::log;

const WORDS: &str = include_str!("english.txt");

#[function_component(Options)]
pub fn options() -> Html {
    html! {
        <>
            <h1>{"Options"}</h1>
            <MnemonicInput />
            <MnemonicDatalist/>
            <button>{"Recover"}</button>
        </>
    }
}

#[function_component(MnemonicInput)]
fn mnemonic_input() -> Html {
    let rows: Vec<_> = (0..4)
        .map(|row| {
            html! {
                <MnemonicRow number={row} />
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
}

#[function_component(MnemonicRow)]
fn mnemonic_row(RowProps { number }: &RowProps) -> Html {
    let columns: Vec<_> = (0..3)
        .map(|column| {
            let index = number * 3 + column + 1;
            html! {
                <MnemonicCell index={index}/>
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
}

#[function_component(MnemonicCell)]
fn mnemonic_cell(CellProps { index }: &CellProps) -> Html {
    let id = format!("word{index}");
    let placeholder = format!("Word {index}");

    let on_input = {
        move |e: InputEvent| {
            let target = e.target();
            let input = target.and_then(|t| t.dyn_into::<HtmlInputElement>().ok());

            if let Some(input) = input {
                input.set_custom_validity("");
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
            <input id={id} oninput={on_input} onchange={on_change} type="text" list="word_list" placeholder={placeholder}/>
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
