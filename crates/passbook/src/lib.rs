//! Proctor Passbook — the consumer credential manager (Phase A).
//!
//! Where `proctor-vault` is the minimal store the *broker* uses, Passbook is the
//! rich domain a person and their family actually use: logins with TOTP and
//! passkeys, secure notes, cards, identities; a device **Secret Key** (2SKD) so a
//! server breach yields uncrackable data even against a weak master password; and
//! a **Watchtower** security analysis (weak / reused passwords).
//!
//! SECURITY NOTE: prototype crypto of the *shape* (Argon2id + XChaCha20-Poly1305
//! + Secret Key). Needs a formal review before real use — see the threat model.

pub mod totp;

use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, thiserror::Error)]
pub enum PassbookError {
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("decryption failed (wrong master password or Secret Key, or tampered data)")]
    Decrypt,
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("bad Secret Key format")]
    SecretKey,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// The category of a vault entry (drives the icon + fields in the UI).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Category {
    Login,
    SecureNote,
    Card,
    Identity,
}

/// A website/app login — the most common entry.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Login {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub urls: Vec<String>,
    /// TOTP shared secret (base32), if the account has 2FA.
    #[serde(default)]
    pub totp_secret: Option<String>,
    /// Whether a passkey (WebAuthn credential) is stored for this login.
    #[serde(default)]
    pub has_passkey: bool,
}

impl Drop for Login {
    fn drop(&mut self) {
        self.password.zeroize();
        if let Some(s) = self.totp_secret.as_mut() {
            s.zeroize();
        }
    }
}

/// A payment card.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Card {
    pub cardholder: String,
    pub number: String,
    pub expiry: String,
    pub cvv: String,
}

impl Drop for Card {
    fn drop(&mut self) {
        self.number.zeroize();
        self.cvv.zeroize();
    }
}

/// An identity (for form-fill).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Identity {
    pub full_name: String,
    pub email: String,
    pub phone: String,
    pub address: String,
}

/// The category-specific content of an entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Content {
    Login(Login),
    SecureNote(String),
    Card(Card),
    Identity(Identity),
}

impl Content {
    pub fn category(&self) -> Category {
        match self {
            Content::Login(_) => Category::Login,
            Content::SecureNote(_) => Category::SecureNote,
            Content::Card(_) => Category::Card,
            Content::Identity(_) => Category::Identity,
        }
    }
}

/// A vault entry: a titled, tagged, categorized credential.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    pub updated_epoch: u64,
    pub content: Content,
}

impl Entry {
    pub fn login(id: &str, title: &str, username: &str, password: &str) -> Entry {
        Entry {
            id: id.into(),
            title: title.into(),
            tags: Vec::new(),
            favorite: false,
            updated_epoch: 0,
            content: Content::Login(Login {
                username: username.into(),
                password: password.into(),
                urls: Vec::new(),
                totp_secret: None,
                has_passkey: false,
            }),
        }
    }

    pub fn category(&self) -> Category {
        self.content.category()
    }
}

// ---------------------------------------------------------------------------
// Secret Key (two-secret key derivation, à la 1Password)
// ---------------------------------------------------------------------------

/// A 128-bit device-generated Secret Key. Combined with the master password so a
/// server breach yields data that is uncrackable without *both* secrets.
#[derive(Clone)]
pub struct SecretKey([u8; 16]);

impl SecretKey {
    /// Generate a fresh random Secret Key.
    pub fn generate() -> Self {
        let mut k = [0u8; 16];
        OsRng.fill_bytes(&mut k);
        SecretKey(k)
    }

    /// Render as a grouped hex string for the Emergency Kit (e.g. `A3-F19C-…`).
    pub fn emergency_kit_format(&self) -> String {
        let hex: String = self.0.iter().map(|b| format!("{b:02X}")).collect();
        hex.as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .collect::<Vec<_>>()
            .join("-")
    }

    pub fn parse(s: &str) -> Result<Self, PassbookError> {
        let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if clean.len() != 32 {
            return Err(PassbookError::SecretKey);
        }
        let mut k = [0u8; 16];
        for (i, byte) in k.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16)
                .map_err(|_| PassbookError::SecretKey)?;
        }
        Ok(SecretKey(k))
    }
}

/// Derive the 32-byte vault key from the master password AND (optionally) the
/// Secret Key. With a Secret Key, `key = SHA256(argon2id(master) || secret_key)`
/// — both secrets are required; the server (holding only ciphertext + salt) can't
/// derive it even against a weak master.
fn derive_key(
    master: &[u8],
    salt: &[u8],
    secret_key: Option<&SecretKey>,
) -> Result<Zeroizing<[u8; 32]>, PassbookError> {
    let mut mk = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(master, salt, mk.as_mut())
        .map_err(|_| PassbookError::KeyDerivation)?;
    let mut key = Zeroizing::new([0u8; 32]);
    match secret_key {
        Some(sk) => {
            let mut h = Sha256::new();
            h.update(mk.as_ref());
            h.update(sk.0);
            key.copy_from_slice(&h.finalize());
        }
        None => key.copy_from_slice(mk.as_ref()),
    }
    Ok(key)
}

/// A sealed (encrypted-at-rest) Passbook vault.
#[derive(Clone, Serialize, Deserialize)]
pub struct SealedVault {
    salt: [u8; 16],
    nonce: [u8; 24],
    /// True if a Secret Key is required to open (2SKD).
    pub secret_key_protected: bool,
    ciphertext: Vec<u8>,
}

/// Seal a set of entries under the master password and (optional) Secret Key.
pub fn seal(
    entries: &[Entry],
    master: &[u8],
    secret_key: Option<&SecretKey>,
) -> Result<SealedVault, PassbookError> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let key = derive_key(master, &salt, secret_key)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| PassbookError::KeyDerivation)?;
    let plaintext = Zeroizing::new(serde_json::to_vec(entries)?);
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext.as_slice())
        .map_err(|_| PassbookError::Decrypt)?;
    Ok(SealedVault {
        salt,
        nonce,
        secret_key_protected: secret_key.is_some(),
        ciphertext,
    })
}

/// Open a sealed vault. Fails on a wrong master/Secret Key or any tampering.
pub fn open(
    sealed: &SealedVault,
    master: &[u8],
    secret_key: Option<&SecretKey>,
) -> Result<Vec<Entry>, PassbookError> {
    let key = derive_key(master, &sealed.salt, secret_key)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| PassbookError::KeyDerivation)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&sealed.nonce),
                sealed.ciphertext.as_ref(),
            )
            .map_err(|_| PassbookError::Decrypt)?,
    );
    Ok(serde_json::from_slice(&plaintext)?)
}

// ---------------------------------------------------------------------------
// Watchtower — security analysis over the vault
// ---------------------------------------------------------------------------

/// A weak/reused/at-risk finding for the security dashboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Issue {
    /// Password below the strength threshold (id, estimated bits).
    Weak(String, u32),
    /// Password reused across multiple logins (the ids sharing it).
    Reused(Vec<String>),
    /// Login has 2FA available but no TOTP stored.
    Missing2fa(String),
}

/// Crude password-strength estimate in bits (character-space × length).
pub fn strength_bits(password: &str) -> u32 {
    if password.is_empty() {
        return 0;
    }
    let mut space = 0u32;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        space += 26;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        space += 26;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        space += 10;
    }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        space += 32;
    }
    let per_char = (space.max(1) as f64).log2();
    (per_char * password.chars().count() as f64) as u32
}

/// Analyze the vault for weak and reused passwords (Watchtower).
pub fn watchtower(entries: &[Entry]) -> Vec<Issue> {
    const WEAK_BELOW_BITS: u32 = 60;
    let mut issues = Vec::new();
    let mut by_password: std::collections::HashMap<&str, Vec<String>> =
        std::collections::HashMap::new();

    for e in entries {
        if let Content::Login(l) = &e.content {
            if !l.password.is_empty() {
                let bits = strength_bits(&l.password);
                if bits < WEAK_BELOW_BITS {
                    issues.push(Issue::Weak(e.id.clone(), bits));
                }
                by_password
                    .entry(l.password.as_str())
                    .or_default()
                    .push(e.id.clone());
            }
        }
    }
    for (_pw, mut ids) in by_password {
        if ids.len() > 1 {
            ids.sort();
            issues.push(Issue::Reused(ids));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<Entry> {
        vec![
            Entry::login("e1", "GitHub", "octo", "S7r0ng!Pass#word_2026"),
            Entry::login("e2", "Bank", "me", "hunter2"), // weak
            Entry::login("e3", "Netflix", "me", "hunter2"), // reused with e2
            Entry {
                id: "e4".into(),
                title: "Recovery codes".into(),
                tags: vec!["personal".into()],
                favorite: true,
                updated_epoch: 0,
                content: Content::SecureNote("codes: 1234 5678".into()),
            },
        ]
    }

    #[test]
    fn seal_open_roundtrip_master_only() {
        let sealed = seal(&sample(), b"master", None).unwrap();
        assert!(!sealed.secret_key_protected);
        let opened = open(&sealed, b"master", None).unwrap();
        assert_eq!(opened.len(), 4);
        assert_eq!(opened[0].title, "GitHub");
    }

    #[test]
    fn secret_key_is_required_when_used() {
        let sk = SecretKey::generate();
        let sealed = seal(&sample(), b"weak", Some(&sk)).unwrap();
        assert!(sealed.secret_key_protected);
        // Right master + right Secret Key opens.
        assert!(open(&sealed, b"weak", Some(&sk)).is_ok());
        // Right master but NO Secret Key fails — the server-breach defense.
        assert!(open(&sealed, b"weak", None).is_err());
        // Right master + WRONG Secret Key fails.
        assert!(open(&sealed, b"weak", Some(&SecretKey::generate())).is_err());
    }

    #[test]
    fn secret_key_emergency_kit_roundtrips() {
        let sk = SecretKey::generate();
        let printed = sk.emergency_kit_format();
        assert!(printed.contains('-'));
        let parsed = SecretKey::parse(&printed).unwrap();
        assert_eq!(sk.0, parsed.0);
    }

    #[test]
    fn watchtower_flags_weak_and_reused() {
        let issues = watchtower(&sample());
        assert!(issues
            .iter()
            .any(|i| matches!(i, Issue::Weak(id, _) if id == "e2")));
        assert!(issues.iter().any(
            |i| matches!(i, Issue::Reused(ids) if ids == &["e2".to_string(), "e3".to_string()])
        ));
        // The strong password isn't flagged weak.
        assert!(!issues
            .iter()
            .any(|i| matches!(i, Issue::Weak(id, _) if id == "e1")));
    }

    #[test]
    fn strength_increases_with_complexity() {
        assert!(strength_bits("hunter2") < strength_bits("S7r0ng!Pass#word_2026"));
    }
}
