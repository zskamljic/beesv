use wasm_bindgen::prelude::*;
use yew::prelude::*;

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
