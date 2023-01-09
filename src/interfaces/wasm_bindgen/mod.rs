use wasm_bindgen::prelude::*;

pub mod generate_cc_keys;
pub mod hybrid_cc_aes;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
    fn alert(s: &str);
}

#[cfg(test)]
mod tests;
