//! Keyward Passbook — WebAssembly bindings.
//!
//! Thin `#[wasm_bindgen]` surface over [`keyward_passbook`] so the vault crypto,
//! TOTP, and Watchtower analysis can run entirely client-side in a browser. The
//! public functions take and return JSON strings (parsed with `serde_json`),
//! which keeps the JS interop boundary simple and framework-agnostic.
//!
//! SECURITY NOTE: this exposes the prototype crypto in `keyward-passbook`
//! (Argon2id, XChaCha20-Poly1305, optional Secret Key). It needs a formal review
//! before real use.
//!
//! (Corrected 2026-07-18: this previously said the browser was "master-password
//! only" and that wiring the device Secret Key was "a planned follow-up". 2SKD
//! is fully wired and used on every seal and open — see [`seal_vault`], which
//! takes the Secret Key. The comment pointed readers at code that contradicted
//! it.)

use keyward_passbook::{
    generate_passphrase, generate_password, new_vault_key, open, open_content, open_sealed,
    safety_number, seal, seal_content, seal_to, sha1_hex, strength_bits, totp, watchtower,
    ContentBlob, Entry, Issue, Member, MemberPublic, PasswordOptions, SealedBox, SealedVault,
    SecretKey, SharedVault,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// 30-second TOTP window (RFC 6238 default), matching `totp::code_now`.
const TOTP_STEP_SECONDS: u64 = 30;

/// Estimate a password's strength in bits.
///
/// Structure-aware: a passphrase built from the bundled wordlist is scored by
/// word entropy (words × log2(list size)); anything else falls back to
/// character-space × length. See `watchtower::strength_bits` for why the
/// character-space estimate alone materially overstated generated passphrases.
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

// ---- Family sharing --------------------------------------------------------
//
// Binary values (32-byte vault keys, X25519 secret/public keys) cross the JS
// boundary as lowercase hex. Opaque aggregates (`SharedVault`, `ContentBlob`)
// cross as their JSON — the app treats them as blobs it stores/relays, never
// inspecting them.

/// Lowercase hex of `bytes`.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse exactly 32 bytes of lowercase hex (a vault key or X25519 key).
fn from_hex_32(s: &str) -> Result<[u8; 32], JsValue> {
    let s = s.trim();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(js_err("expected 64 hex characters"));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(js_err)?;
    }
    Ok(out)
}

/// A member's public identity as it crosses the JS boundary (public key in hex).
#[derive(Deserialize)]
struct MemberPublicJson {
    id: String,
    name: String,
    public_key: String,
    /// Ed25519 verifying key (hex), used to authenticate wrapped-key sets this
    /// member writes.
    ///
    /// Optional so a directory entry published before signing existed still
    /// parses. Absent becomes an all-zero key, which verifies nothing — the
    /// caller gets `Unsigned` rather than a silent pass.
    #[serde(default)]
    signing_key: Option<String>,
}

impl MemberPublicJson {
    fn into_domain(self) -> Result<MemberPublic, JsValue> {
        Ok(MemberPublic {
            id: self.id,
            name: self.name,
            public_key: from_hex_32(&self.public_key)?,
            signing_key: match self.signing_key.as_deref() {
                Some(hex) if !hex.is_empty() => from_hex_32(hex)?,
                _ => [0u8; 32],
            },
        })
    }
}

/// A member's SECRET identity as it crosses the JS boundary: the X25519 secret
/// that unwraps vaults, plus the Ed25519 signing secret that authenticates
/// wrapped-key sets this member writes.
///
/// Both come from the caller's own encrypted vault, never from a relay.
#[derive(Deserialize)]
struct MemberSecretJson {
    id: String,
    #[serde(default)]
    name: String,
    secret: String,
    /// Absent for identities enrolled before signing existed. `Member::from_secrets`
    /// then mints a fresh signing key, so this member can still READ vaults shared
    /// to them; the new public half must be published before anyone can verify
    /// what they WRITE.
    #[serde(default)]
    signing_secret: Option<String>,
}

impl MemberSecretJson {
    fn into_domain(self) -> Result<Member, JsValue> {
        let secret = from_hex_32(&self.secret)?;
        let signing = match self.signing_secret.as_deref() {
            Some(hex) if !hex.is_empty() => Some(from_hex_32(hex)?),
            _ => None,
        };
        Ok(Member::from_secrets(&self.id, &self.name, secret, signing))
    }
}

/// Generate a fresh member X25519 keypair. Returns
/// `{id, name, public_key, secret}` — `public_key` is published to the group,
/// `secret` is stored ENCRYPTED in the member's own vault (never sent to a server).
#[wasm_bindgen]
pub fn member_new(id: &str, name: &str) -> String {
    let m = Member::generate(id, name);
    serde_json::json!({
        "id": id,
        "name": name,
        "public_key": to_hex(&m.public().public_key),
        "secret": to_hex(&m.secret_bytes()),
        "signing_key": to_hex(&m.signing_public()),
        "signing_secret": to_hex(&m.signing_bytes()),
    })
    .to_string()
}

/// Mint a signing key for an identity enrolled before wrapped-key sets were
/// signed. Returns `{signing_key, signing_secret}` (hex).
///
/// Kept separate from `member_new` so upgrading an existing member does NOT
/// touch their X25519 secret — rotating that would orphan every vault already
/// shared to them.
#[wasm_bindgen]
pub fn member_signing_new() -> String {
    let m = Member::generate("", "");
    serde_json::json!({
        "signing_key": to_hex(&m.signing_public()),
        "signing_secret": to_hex(&m.signing_bytes()),
    })
    .to_string()
}

/// Recompute a member's Ed25519 verifying key (hex) from their stored signing
/// secret (hex) — used when re-publishing an existing identity.
#[wasm_bindgen]
pub fn member_signing_public(signing_secret_hex: &str) -> Result<String, JsValue> {
    let signing = from_hex_32(signing_secret_hex)?;
    Ok(to_hex(
        &Member::from_secrets("", "", [0u8; 32], Some(signing)).signing_public(),
    ))
}

/// Recompute a member's public key (hex) from their stored secret (hex) — used
/// when re-publishing an existing identity.
#[wasm_bindgen]
pub fn member_public_key(secret_hex: &str) -> Result<String, JsValue> {
    let secret = from_hex_32(secret_hex)?;
    Ok(to_hex(
        &Member::from_secret("", "", secret).public().public_key,
    ))
}

/// A fresh random 32-byte vault key (hex) — the key the shared content is sealed
/// under and that a `SharedVault` distributes to members.
#[wasm_bindgen]
pub fn generate_vault_key() -> String {
    to_hex(&new_vault_key())
}

/// Seal a JSON array of entries under a vault key (hex), returning a `ContentBlob`
/// as JSON. This is the shared group content every member decrypts.
#[wasm_bindgen]
pub fn seal_group_content(entries_json: &str, vault_key_hex: &str) -> Result<String, JsValue> {
    let entries: Vec<Entry> = serde_json::from_str(entries_json).map_err(js_err)?;
    let key = from_hex_32(vault_key_hex)?;
    let plaintext = serde_json::to_vec(&entries).map_err(js_err)?;
    let blob = seal_content(&key, &plaintext).map_err(js_err)?;
    serde_json::to_string(&blob).map_err(js_err)
}

/// Open a shared `ContentBlob` (JSON) with a vault key (hex), returning the
/// entries as JSON. Fails on a wrong key or any tampering.
#[wasm_bindgen]
pub fn open_group_content(blob_json: &str, vault_key_hex: &str) -> Result<String, JsValue> {
    let blob: ContentBlob = serde_json::from_str(blob_json).map_err(js_err)?;
    let key = from_hex_32(vault_key_hex)?;
    let plaintext = open_content(&blob, &key).map_err(js_err)?;
    let entries: Vec<Entry> = serde_json::from_slice(&plaintext).map_err(js_err)?;
    serde_json::to_string(&entries).map_err(js_err)
}

/// Wrap a vault key (hex) to each member and SIGN the result as `author_json`,
/// returning a `SharedVault` as JSON (the opaque per-member wrapped keys the
/// group relay stores). `members_json` is an array of
/// `{id, name, public_key, signing_key}` (keys in hex); `author_json` is
/// `{id, secret, signing_secret}`.
///
/// The author is required because an UNSIGNED set proves nothing: wrapping needs
/// only the recipients' public keys, so anyone who can read the directory —
/// including the relay — can mint a vault key, wrap it correctly to every real
/// member, and overwrite the blob undetected.
#[wasm_bindgen]
pub fn share_vault_key(
    vault_key_hex: &str,
    members_json: &str,
    author_json: &str,
) -> Result<String, JsValue> {
    let key = from_hex_32(vault_key_hex)?;
    let members: Vec<MemberPublicJson> = serde_json::from_str(members_json).map_err(js_err)?;
    let recipients: Vec<MemberPublic> = members
        .into_iter()
        .map(MemberPublicJson::into_domain)
        .collect::<Result<_, _>>()?;
    let author: MemberSecretJson = serde_json::from_str(author_json).map_err(js_err)?;
    let mut shared = SharedVault::share_to(&key, &recipients).map_err(js_err)?;
    shared.sign_as(&author.into_domain()?);
    serde_json::to_string(&shared).map_err(js_err)
}

/// Recover the vault key (hex) from a `SharedVault` (JSON), first VERIFYING the
/// set was signed by `expected_signer_json` — a `{id, name, public_key,
/// signing_key}` the caller has PINNED locally.
///
/// Verification is not optional and not a separate call: an unwrap that succeeds
/// tells you only that somebody wrapped a key to you, not who. Passing a signer
/// fetched from the same relay that served the blob would prove nothing, since an
/// attacker who can replace the wraps can replace the key beside them.
///
/// Throws `unsigned wrapped-key set` for a legacy or stripped blob and
/// `wrapped-key set signature is invalid` for active tampering — distinct
/// because the first calls for an upgrade prompt and the second for an alarm.
#[wasm_bindgen]
pub fn unwrap_vault_key(
    shared_json: &str,
    member_secret_hex: &str,
    member_id: &str,
    expected_signer_json: &str,
) -> Result<String, JsValue> {
    let shared: SharedVault = serde_json::from_str(shared_json).map_err(js_err)?;
    let signer: MemberPublicJson = serde_json::from_str(expected_signer_json).map_err(js_err)?;
    shared
        .verify_signed_by(&signer.into_domain()?)
        .map_err(js_err)?;
    let secret = from_hex_32(member_secret_hex)?;
    let member = Member::from_secret(member_id, "", secret);
    let key = shared.unwrap_for(&member).map_err(js_err)?;
    Ok(to_hex(&key))
}

/// Unwrap a wrapped-key set that predates signing, WITHOUT authenticating it.
///
/// Refuses if the set carries a signature at all, so this can never be used to
/// skip verifying one that exists — an attacker who strips a signature to force
/// this path gets a set that still has to pass the caller's own
/// "this group has been signed before" check.
///
/// A set opened this way is unauthenticated: it proves someone wrapped a key to
/// you, not who. Callers must surface that and get the set re-signed.
#[wasm_bindgen]
pub fn unwrap_vault_key_unsigned(
    shared_json: &str,
    member_secret_hex: &str,
    member_id: &str,
) -> Result<String, JsValue> {
    let shared: SharedVault = serde_json::from_str(shared_json).map_err(js_err)?;
    if shared.signer().is_some() {
        return Err(JsValue::from_str(
            "this wrapped-key set is signed — verify it instead of opening it unsigned",
        ));
    }
    let secret = from_hex_32(member_secret_hex)?;
    let member = Member::from_secret(member_id, "", secret);
    let key = shared.unwrap_for(&member).map_err(js_err)?;
    Ok(to_hex(&key))
}

/// Sign an existing wrapped-key set as `author_json` without changing its wraps
/// — how a legacy, unsigned set is adopted once a human takes responsibility for
/// it. Refuses an already-signed set, so it cannot overwrite someone else's
/// signature.
#[wasm_bindgen]
pub fn sign_shared_vault(shared_json: &str, author_json: &str) -> Result<String, JsValue> {
    let mut shared: SharedVault = serde_json::from_str(shared_json).map_err(js_err)?;
    if let Some(existing) = shared.signer() {
        return Err(JsValue::from_str(&format!(
            "this wrapped-key set is already signed by {existing}"
        )));
    }
    let author: MemberSecretJson = serde_json::from_str(author_json).map_err(js_err)?;
    shared.sign_as(&author.into_domain()?);
    serde_json::to_string(&shared).map_err(js_err)
}

/// Rotate to a NEW vault key at the next epoch after `previous_json`, wrapped to
/// `members_json` and signed as `author_json`.
///
/// This is the correct call for revocation. Building a fresh set with
/// `share_vault_key` instead would restart the epoch at 1, and the relay could
/// then replay the pre-revocation set — which outranks it — to hand the removed
/// member their access straight back.
#[wasm_bindgen]
pub fn rotate_vault_key(
    previous_json: &str,
    vault_key_hex: &str,
    members_json: &str,
    author_json: &str,
) -> Result<String, JsValue> {
    let previous: SharedVault = serde_json::from_str(previous_json).map_err(js_err)?;
    let key = from_hex_32(vault_key_hex)?;
    let members: Vec<MemberPublicJson> = serde_json::from_str(members_json).map_err(js_err)?;
    let recipients: Vec<MemberPublic> = members
        .into_iter()
        .map(MemberPublicJson::into_domain)
        .collect::<Result<_, _>>()?;
    let author: MemberSecretJson = serde_json::from_str(author_json).map_err(js_err)?;
    let mut rotated = SharedVault::rotate_from(&previous, &key, &recipients).map_err(js_err)?;
    rotated.sign_as(&author.into_domain()?);
    serde_json::to_string(&rotated).map_err(js_err)
}

/// A `SharedVault`'s monotonic epoch.
///
/// Attacker-controlled until the signature verifies — the epoch is inside the
/// signed payload, so a verified set has a trustworthy epoch and an unverified
/// one does not. Callers must pin the highest VERIFIED epoch per group and
/// refuse anything lower.
#[wasm_bindgen]
pub fn shared_vault_epoch(shared_json: &str) -> Result<f64, JsValue> {
    let shared: SharedVault = serde_json::from_str(shared_json).map_err(js_err)?;
    // f64 crosses to JS exactly up to 2^53; epochs increment once per membership
    // change, so that ceiling is unreachable in practice.
    Ok(shared.epoch() as f64)
}

/// Who signed a `SharedVault`, or `null` if it carries no signature.
///
/// Lets a caller look up the right PINNED signer before calling
/// `unwrap_vault_key`. Trust nothing about the answer itself — it is attacker-
/// controlled until verification passes.
#[wasm_bindgen]
pub fn shared_vault_signer(shared_json: &str) -> Result<Option<String>, JsValue> {
    let shared: SharedVault = serde_json::from_str(shared_json).map_err(js_err)?;
    Ok(shared.signer().map(|s| s.to_owned()))
}

/// Add a new member to a `SharedVault` (JSON) — an existing member re-wraps the
/// vault key to `new_member_json` (`{id, name, public_key}`) without the owner.
/// Returns the updated `SharedVault` as JSON.
#[wasm_bindgen]
pub fn grant_group_access(
    shared_json: &str,
    existing_json: &str,
    new_member_json: &str,
    expected_signer_json: &str,
) -> Result<String, JsValue> {
    let mut shared: SharedVault = serde_json::from_str(shared_json).map_err(js_err)?;
    let signer: MemberPublicJson = serde_json::from_str(expected_signer_json).map_err(js_err)?;
    // Verify BEFORE extending. Granting access to a forged set would re-sign the
    // attacker's vault key with a real member's key, laundering it into something
    // every other member accepts.
    shared
        .verify_signed_by(&signer.into_domain()?)
        .map_err(js_err)?;
    let existing: Member = serde_json::from_str::<MemberSecretJson>(existing_json)
        .map_err(js_err)?
        .into_domain()?;
    let new_member: MemberPublicJson = serde_json::from_str(new_member_json).map_err(js_err)?;
    shared
        .grant_access(&existing, &new_member.into_domain()?)
        .map_err(js_err)?;
    shared.sign_as(&existing);
    serde_json::to_string(&shared).map_err(js_err)
}

/// Seal a **recovery payload** (this device's Secret Key) to one family member,
/// so they can hand it back if the Emergency Kit is lost. Returns a `SealedBox` as
/// JSON. The contact still cannot open the vault — the master password is the
/// other 2SKD factor and is never shared. `recipient_json` is
/// `{id, name, public_key}` (public_key in hex).
#[wasm_bindgen]
pub fn seal_recovery(recipient_json: &str, plaintext: &str) -> Result<String, JsValue> {
    let recipient: MemberPublicJson = serde_json::from_str(recipient_json).map_err(js_err)?;
    let sealed = seal_to(&recipient.into_domain()?, plaintext.as_bytes()).map_err(js_err)?;
    serde_json::to_string(&sealed).map_err(js_err)
}

/// Open a recovery payload addressed to this member, returning the plaintext.
/// Fails for anyone else, or on tampering.
#[wasm_bindgen]
pub fn open_recovery(sealed_json: &str, member_secret_hex: &str) -> Result<String, JsValue> {
    let sealed: SealedBox = serde_json::from_str(sealed_json).map_err(js_err)?;
    let secret = from_hex_32(member_secret_hex)?;
    let member = Member::from_secret("", "", secret);
    let bytes = open_sealed(&sealed, &member).map_err(js_err)?;
    String::from_utf8(bytes).map_err(js_err)
}

/// The group's **safety number** — a short fingerprint of the members' public
/// identities that family members compare **out of band** to detect a relay that
/// substituted or added a public key (the key-substitution risk in ADR-0004).
/// `members_json` is an array of `{id, name, public_key}` (public_key in hex).
#[wasm_bindgen]
pub fn group_safety_number(members_json: &str) -> Result<String, JsValue> {
    let members: Vec<MemberPublicJson> = serde_json::from_str(members_json).map_err(js_err)?;
    let domain: Vec<MemberPublic> = members
        .into_iter()
        .map(MemberPublicJson::into_domain)
        .collect::<Result<_, _>>()?;
    Ok(safety_number(&domain))
}

/// Remove a member's wrapped copy from a `SharedVault` (JSON), re-sign it as
/// `author_json` (`{id, secret, signing_secret}`), and return the
/// updated JSON. For TRUE revocation the caller must also rotate the vault key
/// (`generate_vault_key` → `seal_group_content` → `share_vault_key` to the
/// remaining members), since a removed member may retain a key they already read.
#[wasm_bindgen]
pub fn revoke_group_member(
    shared_json: &str,
    member_id: &str,
    author_json: &str,
) -> Result<String, JsValue> {
    let mut shared: SharedVault = serde_json::from_str(shared_json).map_err(js_err)?;
    shared.revoke(member_id);
    // Re-sign: removing a wrap changes the signed payload, so an unsigned or
    // stale-signed set would be indistinguishable from one a relay truncated.
    let author: MemberSecretJson = serde_json::from_str(author_json).map_err(js_err)?;
    shared.sign_as(&author.into_domain()?);
    serde_json::to_string(&shared).map_err(js_err)
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
