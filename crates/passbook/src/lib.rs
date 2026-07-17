//! Proctor Passbook — the consumer credential manager (Phase A).
//!
//! Where `proctor-vault` is the minimal store the *broker* uses, Passbook is the
//! rich domain a person and their family actually use: logins with TOTP and
//! passkeys, secure notes, cards, identities; a device **Secret Key** (2SKD) so a
//! server breach yields uncrackable data even against a weak master password; and
//! a **Watchtower** security analysis (weak / reused passwords).
//!
//! ## Structure (DDD / hexagonal)
//! - [`domain`] — entities ([`Entry`]) and value objects ([`Login`], [`Card`],
//!   [`Identity`], [`Category`], [`SecretKey`]).
//! - [`sealing`] — the sealing service ([`seal`] / [`open`] / [`SealedVault`]),
//!   composing the [`proctor_crypto`] shared kernel with the 2SKD twist.
//! - [`watchtower`] — a domain service (weak/reused analysis).
//! - [`sharing`] — the family-sharing aggregate (per-recipient sealed-box keys).
//! - [`ports`] — driven ports ([`VaultRepository`], [`Clock`]); adapters live in
//!   the outer crates.
//!
//! The crate root re-exports the domain, sealing, watchtower, and port types so
//! the public API is a flat `proctor_passbook::{Entry, seal, open, watchtower, …}`.
//!
//! SECURITY NOTE: prototype crypto of the *shape* (Argon2id + XChaCha20-Poly1305
//! + Secret Key). Needs a formal review before real use — see the threat model.

pub mod domain;
pub mod generate;
pub mod ports;
pub mod sealing;
pub mod sharing;
pub mod totp;
pub mod watchtower;

pub use domain::{Card, Category, Content, Entry, Identity, Login, SecretKey};
pub use generate::{generate_passphrase, generate_password, sha1_hex, PasswordOptions};
pub use ports::{Clock, VaultRepository};
pub use sealing::{open, seal, SealedVault};
pub use watchtower::{strength_bits, watchtower, Issue};

/// The Passbook context's error type (ubiquitous across domain and adapters).
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
