//! Native desktop shell for the Keyward Passbook web vault.
//!
//! This crate is a thin Tauri v2 wrapper: it loads the exact same Vue 3 + Vite
//! frontend that ships as the web vault (dev server on :5173, production build
//! in `../dist`) inside a native window. No business logic lives here — the
//! crypto core runs in-browser via the `passbook-wasm` module, unchanged.

/// Build and run the Tauri application.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running Keyward Passbook desktop application");
}
