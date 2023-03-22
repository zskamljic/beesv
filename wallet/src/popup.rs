use wasm_bindgen::prelude::*;
use yew::prelude::*;

#[wasm_bindgen(inline_js = "export function open_settings() { chrome.runtime.openOptionsPage(); }")]
extern "C" {
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
