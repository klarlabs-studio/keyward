//! Accounts and per-device tokens — the identity side of Sync.
//!
//! An **account** owns exactly one sealed-vault blob (see [`SyncStore`]). A
//! **device token** is an opaque bearer secret that resolves to an account: a
//! user registers once to get their first token, then mints an additional token
//! per new device via the add-a-device flow. Every token of an account maps to
//! the same `account_id`, so all a user's devices read and write the one vault.
//!
//! Zero-knowledge is preserved: tokens and account ids are random 128-bit hex
//! with no relationship to the master password or Secret Key, and this registry
//! never touches the vault blob itself.
//!
//! [`AccountStore`] is the port; [`MemoryAccountStore`] and [`FileAccountStore`]
//! are the adapters. The [`FileAccountStore`] persists to `accounts.json` in the
//! same directory the [`FileStore`] uses.
//!
//! [`SyncStore`]: crate::SyncStore
//! [`FileStore`]: crate::FileStore

use crate::SyncError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

/// The result of registering: an account and its first device token.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Account {
    pub account_id: String,
    /// Opaque bearer secret for the freshly registered device.
    pub device_token: String,
}

/// The driven port for accounts and per-device tokens.
///
/// Implementations map opaque device tokens to account ids. A token is a
/// secret; it is never derived from user data and only ever compared for
/// equality — never logged.
pub trait AccountStore {
    /// Register a new account with an optional contact email, returning the
    /// account id and its first device token.
    fn register(&self, email: Option<&str>) -> Result<Account, SyncError>;

    /// Mint an additional device token for the account that `existing_token`
    /// already belongs to. Returns the new token, or `None` if the presented
    /// token is unknown.
    fn add_device(&self, existing_token: &str) -> Result<Option<String>, SyncError>;

    /// Resolve a device token to its `account_id`, or `None` if unknown.
    fn account_for_token(&self, token: &str) -> Result<Option<String>, SyncError>;
}

/// Generate a random 128-bit identifier as lowercase hex (32 chars).
fn random_hex_id() -> String {
    let bits: u128 = rand::random();
    format!("{bits:032x}")
}

/// The registry's serializable state: which tokens map to which accounts, and
/// each account's optional email. Kept minimal — no vault data ever lives here.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Registry {
    /// device token -> account id
    tokens: HashMap<String, String>,
    /// account id -> optional contact email
    emails: HashMap<String, Option<String>>,
}

impl Registry {
    fn register(&mut self, email: Option<&str>) -> Account {
        let account_id = random_hex_id();
        let device_token = random_hex_id();
        self.tokens.insert(device_token.clone(), account_id.clone());
        self.emails
            .insert(account_id.clone(), email.map(str::to_string));
        Account {
            account_id,
            device_token,
        }
    }

    fn add_device(&mut self, existing_token: &str) -> Option<String> {
        let account_id = self.tokens.get(existing_token)?.clone();
        let device_token = random_hex_id();
        self.tokens.insert(device_token.clone(), account_id);
        Some(device_token)
    }

    fn account_for_token(&self, token: &str) -> Option<String> {
        self.tokens.get(token).cloned()
    }
}

/// In-memory account registry (tests, and a stateless dev server).
#[derive(Default)]
pub struct MemoryAccountStore {
    inner: Mutex<Registry>,
}

impl MemoryAccountStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AccountStore for MemoryAccountStore {
    fn register(&self, email: Option<&str>) -> Result<Account, SyncError> {
        Ok(self.inner.lock().unwrap().register(email))
    }

    fn add_device(&self, existing_token: &str) -> Result<Option<String>, SyncError> {
        Ok(self.inner.lock().unwrap().add_device(existing_token))
    }

    fn account_for_token(&self, token: &str) -> Result<Option<String>, SyncError> {
        Ok(self.inner.lock().unwrap().account_for_token(token))
    }
}

/// Filesystem-backed account registry: the whole [`Registry`] is persisted as a
/// single `accounts.json` under `dir` (the same directory the [`FileStore`]
/// uses). A process mutex serializes read-modify-write so concurrent requests
/// don't clobber each other.
///
/// [`FileStore`]: crate::FileStore
pub struct FileAccountStore {
    path: PathBuf,
    guard: Mutex<()>,
}

impl FileAccountStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            path: dir.into().join("accounts.json"),
            guard: Mutex::new(()),
        }
    }

    fn read(&self) -> Result<Registry, SyncError> {
        if !self.path.exists() {
            return Ok(Registry::default());
        }
        let bytes = std::fs::read(&self.path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn write(&self, registry: &Registry) -> Result<(), SyncError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, serde_json::to_vec(registry)?)?;
        Ok(())
    }
}

impl AccountStore for FileAccountStore {
    fn register(&self, email: Option<&str>) -> Result<Account, SyncError> {
        let _lock = self.guard.lock().unwrap();
        let mut registry = self.read()?;
        let account = registry.register(email);
        self.write(&registry)?;
        Ok(account)
    }

    fn add_device(&self, existing_token: &str) -> Result<Option<String>, SyncError> {
        let _lock = self.guard.lock().unwrap();
        let mut registry = self.read()?;
        match registry.add_device(existing_token) {
            Some(token) => {
                self.write(&registry)?;
                Ok(Some(token))
            }
            None => Ok(None),
        }
    }

    fn account_for_token(&self, token: &str) -> Result<Option<String>, SyncError> {
        let _lock = self.guard.lock().unwrap();
        Ok(self.read()?.account_for_token(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account_suite(store: &dyn AccountStore) {
        // Register issues a token that resolves back to the new account.
        let alice = store.register(Some("alice@example.com")).unwrap();
        assert_eq!(
            store.account_for_token(&alice.device_token).unwrap(),
            Some(alice.account_id.clone())
        );

        // add_device issues a SECOND token resolving to the SAME account.
        let second = store.add_device(&alice.device_token).unwrap().unwrap();
        assert_ne!(second, alice.device_token);
        assert_eq!(
            store.account_for_token(&second).unwrap(),
            Some(alice.account_id.clone())
        );

        // An unknown token resolves to None.
        assert_eq!(store.account_for_token("deadbeef").unwrap(), None);
        // add_device on an unknown token is a no-op returning None.
        assert_eq!(store.add_device("deadbeef").unwrap(), None);

        // Two registrations get distinct accounts.
        let bob = store.register(None).unwrap();
        assert_ne!(bob.account_id, alice.account_id);
        assert_ne!(bob.device_token, alice.device_token);
        assert_eq!(
            store.account_for_token(&bob.device_token).unwrap(),
            Some(bob.account_id)
        );
    }

    #[test]
    fn memory_account_store_register_add_device_resolve() {
        account_suite(&MemoryAccountStore::new());
    }

    #[test]
    fn file_account_store_register_add_device_resolve() {
        let dir =
            std::env::temp_dir().join(format!("proctor-accounts-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = FileAccountStore::new(&dir);
        account_suite(&store);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_account_store_persists_across_instances() {
        let dir =
            std::env::temp_dir().join(format!("proctor-accounts-persist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let token = {
            let store = FileAccountStore::new(&dir);
            store.register(None).unwrap().device_token
        };
        // A fresh instance over the same dir still resolves the token.
        let reopened = FileAccountStore::new(&dir);
        assert!(reopened.account_for_token(&token).unwrap().is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ids_and_tokens_are_128_bit_hex() {
        let id = random_hex_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
