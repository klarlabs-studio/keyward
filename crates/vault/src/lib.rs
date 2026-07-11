//! Proctor encrypted vault core — **PROTOTYPE**.
//!
//! Demonstrates the real cryptographic shape of a Proctor vault: an Argon2id
//! key-derivation over the user's secret material sealing the serialized item
//! store with XChaCha20-Poly1305 AEAD. The item *secrets* never leave this
//! crate as plaintext to the broker; the broker only ever sees [`ItemRef`]
//! metadata (see `proctor-broker`).
//!
//! SECURITY NOTE: this is a prototype of the *shape*, not an audited
//! implementation. Before any real use it needs: a device-generated Secret Key
//! folded into KDF (two-secret key derivation), tuned Argon2 parameters,
//! per-item keys, authenticated associated data, and a formal review.

use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("decryption failed (wrong secret or tampered data)")]
    Decrypt,
    #[error("serialization failed: {0}")]
    Serde(#[from] serde_json::Error),
}

/// The kind of credential an item holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ItemKind {
    Password,
    ApiKey,
    TotpSeed,
    Note,
}

/// A vault item as stored (contains the secret; serialized only inside the sealed blob).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Item {
    pub id: String,
    pub label: String,
    pub kind: ItemKind,
    /// Origins this credential is bound to. The broker refuses any use against
    /// an origin not in this list — the anti-confused-deputy guarantee.
    pub bound_origins: Vec<String>,
    /// Whether the broker may mint a short-lived scoped token from this item
    /// instead of ever handing over the durable secret.
    pub mintable: bool,
    /// The durable secret. Never exposed to the broker or any agent by default.
    pub secret: String,
}

/// Metadata-only view safe to hand to the broker. Deliberately omits `secret`.
#[derive(Clone, Debug)]
pub struct ItemRef {
    pub id: String,
    pub label: String,
    pub bound_origins: Vec<String>,
    pub mintable: bool,
}

impl Item {
    /// Project to a secret-free reference for the broker.
    pub fn as_ref_meta(&self) -> ItemRef {
        ItemRef {
            id: self.id.clone(),
            label: self.label.clone(),
            bound_origins: self.bound_origins.clone(),
            mintable: self.mintable,
        }
    }
}

/// A sealed (encrypted-at-rest) vault blob.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedVault {
    salt: [u8; 16],
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

fn derive_key(secret: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(secret, salt, key.as_mut())
        .map_err(|_| VaultError::KeyDerivation)?;
    Ok(key)
}

/// Seal a set of items under the user's secret material.
pub fn seal(items: &[Item], secret: &[u8]) -> Result<SealedVault, VaultError> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let key = derive_key(secret, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| VaultError::KeyDerivation)?;

    let plaintext = Zeroizing::new(serde_json::to_vec(items)?);
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext.as_slice())
        .map_err(|_| VaultError::Decrypt)?;

    Ok(SealedVault { salt, nonce, ciphertext })
}

/// Open a sealed vault. Fails on wrong secret or any tampering (AEAD auth).
pub fn open(sealed: &SealedVault, secret: &[u8]) -> Result<Vec<Item>, VaultError> {
    let key = derive_key(secret, &sealed.salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| VaultError::KeyDerivation)?;
    let plaintext = cipher
        .decrypt(XNonce::from_slice(&sealed.nonce), sealed.ciphertext.as_ref())
        .map_err(|_| VaultError::Decrypt)?;
    let items = serde_json::from_slice(&plaintext)?;
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<Item> {
        vec![Item {
            id: "itm_github".into(),
            label: "GitHub".into(),
            kind: ItemKind::ApiKey,
            bound_origins: vec!["github.com".into()],
            mintable: true,
            secret: "ghp_supersecret".into(),
        }]
    }

    #[test]
    fn seal_open_roundtrip() {
        let items = sample();
        let sealed = seal(&items, b"correct horse battery staple").unwrap();
        let opened = open(&sealed, b"correct horse battery staple").unwrap();
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].secret, "ghp_supersecret");
    }

    #[test]
    fn wrong_secret_fails() {
        let sealed = seal(&sample(), b"right").unwrap();
        assert!(matches!(open(&sealed, b"wrong"), Err(VaultError::Decrypt)));
    }

    #[test]
    fn tamper_is_detected() {
        let mut sealed = seal(&sample(), b"right").unwrap();
        // Flip a ciphertext byte — AEAD must reject.
        sealed.ciphertext[0] ^= 0xff;
        assert!(open(&sealed, b"right").is_err());
    }

    #[test]
    fn item_ref_omits_secret() {
        let r = sample()[0].as_ref_meta();
        assert_eq!(r.id, "itm_github");
        assert!(r.mintable);
        // ItemRef has no `secret` field at all — enforced at the type level.
    }
}
