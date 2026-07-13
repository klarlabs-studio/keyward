//! Sealing service — turns the entry aggregate into an encrypted-at-rest
//! [`SealedVault`] and back, composing the shared [`proctor_crypto`] kernel with
//! the Passbook-specific 2SKD twist (folding in the device Secret Key).
//!
//! The wire format is deliberately stable: `salt` (16) + `nonce` (24) +
//! `secret_key_protected` flag + `ciphertext`. Argon2id derives the master key
//! from the salt; when a Secret Key is present the vault key is
//! `SHA256(argon2id(master) || secret_key)`, so ciphertext plus salt is useless
//! to a server that lacks the device Secret Key.

use crate::domain::{Entry, SecretKey};
use crate::PassbookError;
use proctor_crypto::{
    aead_open, aead_seal, derive_key_argon2id, random_array, KEY_LEN, NONCE_LEN, SALT_LEN,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Derive the 32-byte vault key from the master password AND (optionally) the
/// Secret Key. Without a Secret Key this is the Argon2id output directly; with
/// one it is `SHA256(argon2id(master) || secret_key)`.
fn derive_key(
    master: &[u8],
    salt: &[u8],
    secret_key: Option<&SecretKey>,
) -> Result<Zeroizing<[u8; KEY_LEN]>, PassbookError> {
    let mk = derive_key_argon2id(master, salt).map_err(|_| PassbookError::KeyDerivation)?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    match secret_key {
        Some(sk) => {
            let mut h = Sha256::new();
            h.update(mk.as_ref());
            h.update(sk.bytes());
            key.copy_from_slice(&h.finalize());
        }
        None => key.copy_from_slice(mk.as_ref()),
    }
    Ok(key)
}

/// A sealed (encrypted-at-rest) Passbook vault.
#[derive(Clone, Serialize, Deserialize)]
pub struct SealedVault {
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
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
    let salt = random_array::<SALT_LEN>();
    let nonce = random_array::<NONCE_LEN>();
    let key = derive_key(master, &salt, secret_key)?;
    let plaintext = Zeroizing::new(serde_json::to_vec(entries)?);
    let ciphertext =
        aead_seal(&key, &nonce, plaintext.as_slice()).map_err(|_| PassbookError::Decrypt)?;
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
    let plaintext = Zeroizing::new(
        aead_open(&key, &sealed.nonce, sealed.ciphertext.as_ref())
            .map_err(|_| PassbookError::Decrypt)?,
    );
    Ok(serde_json::from_slice(&plaintext)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<Entry> {
        vec![
            Entry::login("e1", "GitHub", "octo", "S7r0ng!Pass#word_2026"),
            Entry::login("e2", "Bank", "me", "hunter2"),
        ]
    }

    #[test]
    fn seal_open_roundtrip_master_only() {
        let sealed = seal(&sample(), b"master", None).unwrap();
        assert!(!sealed.secret_key_protected);
        let opened = open(&sealed, b"master", None).unwrap();
        assert_eq!(opened.len(), 2);
        assert_eq!(opened[0].title, "GitHub");
    }

    #[test]
    fn secret_key_is_required_when_used() {
        let sk = SecretKey::generate();
        let sealed = seal(&sample(), b"weak", Some(&sk)).unwrap();
        assert!(sealed.secret_key_protected);
        assert!(open(&sealed, b"weak", Some(&sk)).is_ok());
        // Right master but NO Secret Key fails — the server-breach defense.
        assert!(open(&sealed, b"weak", None).is_err());
        // Right master + WRONG Secret Key fails.
        assert!(open(&sealed, b"weak", Some(&SecretKey::generate())).is_err());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let mut sealed = seal(&sample(), b"master", None).unwrap();
        sealed.ciphertext[0] ^= 0xff;
        assert!(open(&sealed, b"master", None).is_err());
    }
}
