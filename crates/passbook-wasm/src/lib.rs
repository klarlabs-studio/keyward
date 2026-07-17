//! Proctor Passbook — WebAssembly bindings.
//!
//! Thin `#[wasm_bindgen]` surface over [`proctor_passbook`] so the vault crypto,
//! TOTP, and Watchtower analysis can run entirely client-side in a browser. The
//! public functions take and return JSON strings (parsed with `serde_json`),
//! which keeps the JS interop boundary simple and framework-agnostic.
//!
//! SECURITY NOTE: this exposes the prototype crypto in `proctor-passbook`
//! (Argon2id, XChaCha20-Poly1305, optional Secret Key). It needs a formal review
//! before real use. The browser prototype is master-password only; wiring the
//! device Secret Key (2SKD) through these bindings is a planned follow-up — see
//! [`seal_vault`].

use proctor_passbook::{
    generate_passphrase, generate_password, open, seal, sha1_hex, strength_bits, totp, watchtower,
    Entry, Issue, PasswordOptions, SealedVault, SecretKey,
};
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// 30-second TOTP window (RFC 6238 default), matching `totp::code_now`.
const TOTP_STEP_SECONDS: u64 = 30;

/// Estimate a password's strength in bits (character-space × length).
#[wasm_bindgen]
pub fn password_strength(password: &str) -> u32 {
    strength_bits(password)
}

/// Generate a random password with the given classes and length.
#[wasm_bindgen]
pub fn generate_pw(
    length: u32,
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: bool,
    avoid_ambiguous: bool,
) -> String {
    generate_password(&PasswordOptions {
        length: length as usize,
        lowercase,
        uppercase,
        digits,
        symbols,
        avoid_ambiguous,
    })
}

/// Generate a passphrase of `words` random words joined by `separator`.
#[wasm_bindgen]
pub fn generate_pp(words: u32, separator: &str) -> String {
    generate_passphrase(words as usize, separator)
}

/// SHA-1 (uppercase hex) of a password — for HaveIBeenPwned k-anonymity. The
/// caller sends only the first 5 chars to the API and matches the suffix locally.
#[wasm_bindgen]
pub fn password_sha1(password: &str) -> String {
    sha1_hex(password)
}

/// The current 6-digit / 30-second TOTP code for a base32 secret.
///
/// `unix_time` is a JS `number` (seconds since the epoch, an `f64`); it is
/// truncated to a whole second. Returns `undefined` in JS if the secret is not
/// valid base32.
#[wasm_bindgen]
pub fn totp_code(secret_base32: &str, unix_time: f64) -> Option<String> {
    totp::code_now(secret_base32, unix_time as u64)
}

/// Seconds remaining in the current 30-second TOTP window (for a countdown ring).
#[wasm_bindgen]
pub fn totp_seconds_remaining(unix_time: f64) -> u32 {
    totp::seconds_remaining(unix_time as u64, TOTP_STEP_SECONDS) as u32
}

/// A JSON-serializable view of [`Issue`] (the domain enum is not `Serialize`).
///
/// Rendered as a tagged object, e.g. `{"kind":"weak","id":"e2","bits":33}`.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum IssueJson {
    Weak { id: String, bits: u32 },
    Reused { ids: Vec<String> },
    Missing2fa { id: String },
}

impl From<&Issue> for IssueJson {
    fn from(issue: &Issue) -> Self {
        match issue {
            Issue::Weak(id, bits) => IssueJson::Weak {
                id: id.clone(),
                bits: *bits,
            },
            Issue::Reused(ids) => IssueJson::Reused { ids: ids.clone() },
            Issue::Missing2fa(id) => IssueJson::Missing2fa { id: id.clone() },
        }
    }
}

/// Run Watchtower over a JSON array of entries and return the findings as JSON.
///
/// On malformed input, returns a JSON object describing the parse error rather
/// than throwing, so callers can render it directly.
#[wasm_bindgen]
pub fn watchtower_json(entries_json: &str) -> String {
    let entries: Vec<Entry> = match serde_json::from_str(entries_json) {
        Ok(entries) => entries,
        Err(err) => return format!("{{\"error\":{}}}", json_string(&err.to_string())),
    };
    let issues: Vec<IssueJson> = watchtower(&entries).iter().map(IssueJson::from).collect();
    // Serializing a Vec<IssueJson> to a string cannot fail here.
    serde_json::to_string(&issues).unwrap_or_else(|_| "[]".to_string())
}

/// Parse an optional Emergency-Kit Secret Key string into a [`SecretKey`].
///
/// `None`/absent → a master-only vault. `Some(s)` → 2SKD, where the derived key
/// mixes in the device Secret Key so a stolen sealed blob is uncrackable without
/// both factors. An empty/whitespace string is treated as absent.
fn parse_secret_key(secret_key: Option<String>) -> Result<Option<SecretKey>, JsValue> {
    match secret_key {
        Some(s) if !s.trim().is_empty() => Ok(Some(SecretKey::parse(&s).map_err(js_err)?)),
        _ => Ok(None),
    }
}

/// Generate a fresh device Secret Key, formatted for the Emergency Kit.
#[wasm_bindgen]
pub fn generate_secret_key() -> String {
    SecretKey::generate().emergency_kit_format()
}

/// True if `s` is a well-formed Secret Key (32 hex digits, grouping ignored).
#[wasm_bindgen]
pub fn secret_key_is_valid(s: &str) -> bool {
    SecretKey::parse(s).is_ok()
}

/// Seal a JSON array of entries under a master password (and optional Secret
/// Key), returning the [`SealedVault`] as JSON.
///
/// Pass `null` for `secret_key` to seal master-only; pass the Emergency-Kit
/// string to seal with 2SKD.
#[wasm_bindgen]
pub fn seal_vault(
    entries_json: &str,
    master: &str,
    secret_key: Option<String>,
) -> Result<String, JsValue> {
    let entries: Vec<Entry> = serde_json::from_str(entries_json).map_err(js_err)?;
    let sk = parse_secret_key(secret_key)?;
    let sealed = seal(&entries, master.as_bytes(), sk.as_ref()).map_err(js_err)?;
    serde_json::to_string(&sealed).map_err(js_err)
}

/// Open a sealed vault (as JSON) with a master password (and optional Secret
/// Key), returning the entries as JSON. Fails on a wrong master password, a
/// missing/wrong Secret Key, or any tampering.
#[wasm_bindgen]
pub fn open_vault(
    sealed_json: &str,
    master: &str,
    secret_key: Option<String>,
) -> Result<String, JsValue> {
    let sealed: SealedVault = serde_json::from_str(sealed_json).map_err(js_err)?;
    let sk = parse_secret_key(secret_key)?;
    let entries = open(&sealed, master.as_bytes(), sk.as_ref()).map_err(js_err)?;
    serde_json::to_string(&entries).map_err(js_err)
}

/// Map any `Display` error into a `JsValue` (thrown as a JS exception).
fn js_err(err: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&err.to_string())
}

/// Minimal JSON string escaper for embedding an error message in a literal.
fn json_string(s: &str) -> String {
    // `serde_json` guarantees a string value serializes without error.
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}
