//! Native desktop shell for the Keyward Passbook web vault.
//!
//! The window is a thin Tauri v2 wrapper around the exact same Vue 3 + Vite
//! frontend that ships as the web vault; the crypto core runs in-browser via the
//! `passbook-wasm` module, unchanged.
//!
//! Beyond the window, this crate also hosts the **desktop autofill agent**
//! (ADR-0007, issue #13): a background listener on a user-private local socket
//! that answers the browser extension from an unlocked session, replacing the
//! prototype bridge's plaintext master-password file.
//!
//! ## Where the session lives
//!
//! ADR-0007 speaks of the agent "holding the session", but in this architecture
//! the decrypted vault lives in the **WebView**, not this Rust process — the
//! crypto is WASM in the browser. So the agent cannot read the session; it must
//! be *fed* it. The frontend calls [`bridge_set_session`] the moment it unlocks
//! and [`bridge_lock`] the moment it locks. Between those, the plaintext logins
//! are held in this process's memory (zeroized on lock, best-effort), and the
//! agent serves them. The consequence — plaintext logins crossing from the
//! WebView into the core process while unlocked — is the security-relevant choice
//! this slice makes concrete; see the ADR addendum.
//!
//! The agent is **locked by default**: the socket binds at startup with an empty,
//! locked session, so it is inert (answers `ping`, refuses `get`, lists nothing)
//! until the frontend unlocks it. Wiring the frontend callers is the next slice
//! and needs the running GUI to verify.

use keyward_passbook::bridge::Session;
use keyward_passbook::Entry;
use std::sync::{Arc, Mutex};

/// The autofill agent's held session, shared between the Tauri commands the
/// unlocked frontend drives (writers) and the background agent thread that
/// answers the extension (reader). `Arc<Mutex<_>>` because those live on
/// different threads.
type AgentSession = Arc<Mutex<Session>>;

/// Hand the agent the freshly-unlocked logins. Called by the frontend the instant
/// the vault unlocks in the WebView — the only place the decrypted entries exist.
/// The frontend may pass the whole entry set; the bridge filters to logins for the
/// current page's origin at query time (ADR-0007 §4), so no pre-filtering here.
#[tauri::command]
fn bridge_set_session(entries: Vec<Entry>, state: tauri::State<'_, AgentSession>) {
    let mut session = state.lock().unwrap_or_else(|e| e.into_inner());
    session.unlock(entries);
}

/// Lock the agent — drop and zeroize the held logins. Called by the frontend when
/// the vault locks, on sign-out, and on idle timeout. After this the agent refuses
/// `get` and lists nothing until the next [`bridge_set_session`].
#[tauri::command]
fn bridge_lock(state: tauri::State<'_, AgentSession>) {
    let mut session = state.lock().unwrap_or_else(|e| e.into_inner());
    session.lock();
}

/// The base directory for the agent socket. Linux: `$XDG_RUNTIME_DIR` — a per-user
/// tmpfs, `0700`, cleaned on logout. macOS/other: the per-user temp dir, itself
/// `0700` under `/var/folders`. The agent creates a `0700` `keyward/` subdirectory
/// inside whichever this returns (ADR-0007 §1).
#[cfg(unix)]
fn runtime_dir() -> std::path::PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(std::env::temp_dir)
}

/// Build and run the Tauri application.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Locked at startup: no secret needs to exist for the socket to come up.
    let session: AgentSession = Arc::new(Mutex::new(Session::locked()));

    tauri::Builder::default()
        .manage(Arc::clone(&session))
        .invoke_handler(tauri::generate_handler![bridge_set_session, bridge_lock])
        .setup(move |_app| {
            // Bring up the autofill agent. It binds a user-private socket and
            // serves the *locked* session, so nothing is exposed until the
            // frontend unlocks it. A failure here (no runtime dir, socket taken)
            // must not stop the vault GUI — the bridge is an add-on, not a
            // prerequisite, so we log and carry on rather than propagate.
            //
            // Unix only for now; Windows autofill uses a named pipe (a later
            // slice under #13) and is deliberately not faked here.
            #[cfg(unix)]
            {
                use keyward_passbook::bridge::ipc;
                match ipc::spawn_agent(
                    &runtime_dir(),
                    Arc::clone(&session),
                    env!("CARGO_PKG_VERSION"),
                ) {
                    Ok(path) => {
                        eprintln!("keyward: autofill agent listening at {}", path.display())
                    }
                    Err(e) => eprintln!("keyward: autofill agent unavailable: {e}"),
                }
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Keyward Passbook desktop application");
}
