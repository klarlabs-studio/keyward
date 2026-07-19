//! Keyward shared cryptographic kernel.
//!
//! In DDD terms this is a **shared kernel**: the small set of cryptographic
//! primitives that both vault bounded contexts — the developer `keyward-vault`
//! and the consumer `keyward-passbook` — agree to depend on, so the construction
//! is defined once and identically. Each context composes these primitives into
//! its own sealing service (Passbook additionally folds in a device Secret Key
//! for 2SKD); the primitives themselves make no policy decisions.
//!
//! Construction: Argon2id (default params) for key derivation, XChaCha20-Poly1305
//! for authenticated encryption, a 16-byte salt and 24-byte nonce.
//!
//! SECURITY NOTE: prototype-grade parameters. A production deployment needs tuned
//! Argon2 cost parameters and a formal review — see the threat model.

use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

/// Salt length for key derivation (bytes).
pub const SALT_LEN: usize = 16;
/// XChaCha20-Poly1305 nonce length (bytes).
pub const NONCE_LEN: usize = 24;
/// Derived symmetric key length (bytes).
pub const KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("AEAD operation failed (wrong key or tampered data)")]
    Aead,
}

/// Fill a buffer with cryptographically secure random bytes.
pub fn fill_random(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}

/// A fresh array of `N` cryptographically secure random bytes.
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut a = [0u8; N];
    OsRng.fill_bytes(&mut a);
    a
}

/// Derive a 32-byte key from `secret` and `salt` with Argon2id (default params).
///
/// Deterministic for a given `(secret, salt)` — the same inputs always yield the
/// same key, which is what lets a sealed blob be reopened.
pub fn derive_key_argon2id(
    secret: &[u8],
    salt: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::default()
        .hash_password_into(secret, salt, key.as_mut())
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(key)
}

/// Seal `plaintext` under `key` and `nonce` with XChaCha20-Poly1305.
pub fn aead_seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::KeyDerivation)?;
    cipher
        .encrypt(XNonce::from_slice(nonce), plaintext)
        .map_err(|_| CryptoError::Aead)
}

/// Open a sealed blob. Fails on a wrong key or any tampering.
pub fn aead_open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::KeyDerivation)?;
    cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| CryptoError::Aead)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_is_deterministic_and_salt_sensitive() {
        let salt_a = [7u8; SALT_LEN];
        let salt_b = [9u8; SALT_LEN];
        let k1 = derive_key_argon2id(b"master", &salt_a).unwrap();
        let k2 = derive_key_argon2id(b"master", &salt_a).unwrap();
        let k3 = derive_key_argon2id(b"master", &salt_b).unwrap();
        assert_eq!(*k1, *k2, "same secret+salt derives the same key");
        assert_ne!(*k1, *k3, "a different salt derives a different key");
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = random_array::<KEY_LEN>();
        let nonce = random_array::<NONCE_LEN>();
        let ct = aead_seal(&key, &nonce, b"attack at dawn").unwrap();
        let pt = aead_open(&key, &nonce, &ct).unwrap();
        assert_eq!(pt, b"attack at dawn");
    }

    #[test]
    fn wrong_key_fails() {
        let nonce = random_array::<NONCE_LEN>();
        let ct = aead_seal(&random_array::<KEY_LEN>(), &nonce, b"secret").unwrap();
        assert!(aead_open(&random_array::<KEY_LEN>(), &nonce, &ct).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = random_array::<KEY_LEN>();
        let nonce = random_array::<NONCE_LEN>();
        let mut ct = aead_seal(&key, &nonce, b"secret").unwrap();
        ct[0] ^= 0xff;
        assert!(aead_open(&key, &nonce, &ct).is_err());
    }

    #[test]
    fn random_arrays_differ() {
        assert_ne!(random_array::<32>(), random_array::<32>());
    }
}
