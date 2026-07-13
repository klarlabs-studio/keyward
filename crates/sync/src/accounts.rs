//! Accounts and per-device tokens — the identity side of Sync.
//!
//! An **account** owns exactly one sealed-vault blob (see [`SyncStore`]). Each
//! **device** has an opaque bearer **token** that resolves to its account; a user
//! registers once for their first device+token, then mints one per new device.
//! All of an account's devices read and write the one vault.
//!
//! Tokens are secrets, so — like passwords — the registry stores only their
//! **SHA-256 hash**. A breached `accounts.json` yields no usable tokens: an
//! attacker cannot reverse a hash back into a bearer credential. The plaintext
//! token is returned exactly once (at register / add-device) and never persisted.
//! Devices can be listed and **revoked** (the lost-device story).
//!
//! Zero-knowledge is preserved: ids/tokens are random 128-bit hex unrelated to
//! the master password or Secret Key, and this registry never touches the vault.
//!
//! [`AccountStore`] is the port; [`MemoryAccountStore`]/[`FileAccountStore`] are
//! the adapters (the latter persists `accounts.json` beside the [`FileStore`]).
//!
//! [`SyncStore`]: crate::SyncStore
//! [`FileStore`]: crate::FileStore

use crate::SyncError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

/// The result of register / add-device: the account, the device's one-time
/// plaintext token, and the device id.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Account {
    pub account_id: String,
    /// Opaque bearer secret — shown once, never stored (only its hash is).
    pub device_token: String,
    pub device_id: String,
}

/// What a presented token resolves to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenIdentity {
    pub account_id: String,
    pub device_id: String,
}

/// A device as shown in the management list — no token or hash.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceInfo {
    pub id: String,
    pub label: String,
    pub created_epoch: u64,
}

/// The driven port for accounts, per-device tokens, and device management.
pub trait AccountStore {
    /// Register a new account (optional contact email) with its first device
    /// (`label`, created at `now`). Returns the account id, one-time token, and
    /// device id.
    fn register(&self, email: Option<&str>, label: &str, now: u64) -> Result<Account, SyncError>;

    /// Mint an additional device for the account that `existing_token` belongs
    /// to. `None` if the presented token is unknown.
    fn add_device(
        &self,
        existing_token: &str,
        label: &str,
        now: u64,
    ) -> Result<Option<Account>, SyncError>;

    /// Resolve a device token to its account + device, or `None` if unknown or
    /// revoked.
    fn resolve_token(&self, token: &str) -> Result<Option<TokenIdentity>, SyncError>;

    /// List an account's devices (no secrets).
    fn list_devices(&self, account_id: &str) -> Result<Vec<DeviceInfo>, SyncError>;

    /// Revoke a device (cut off a lost/stolen device's token). Returns whether a
    /// matching device existed.
    fn revoke_device(&self, account_id: &str, device_id: &str) -> Result<bool, SyncError>;
}

/// Generate a random 128-bit identifier as lowercase hex (32 chars).
fn random_hex_id() -> String {
    let bits: u128 = rand::random();
    format!("{bits:032x}")
}

/// SHA-256 of a token, as 64-char lowercase hex — what we store instead of the
/// token itself.
fn token_hash(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// A stored device: its id, label, creation time, and the *hash* of its token.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct DeviceRecord {
    id: String,
    label: String,
    created_epoch: u64,
    token_hash: String,
}

impl DeviceRecord {
    fn info(&self) -> DeviceInfo {
        DeviceInfo {
            id: self.id.clone(),
            label: self.label.clone(),
            created_epoch: self.created_epoch,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct AccountRecord {
    email: Option<String>,
    devices: Vec<DeviceRecord>,
}

/// The registry state: accounts, each holding its devices (by token hash). No
/// plaintext token and no vault data ever lives here.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Registry {
    accounts: HashMap<String, AccountRecord>,
}

impl Registry {
    fn new_device(&mut self, account_id: &str, label: &str, now: u64) -> Account {
        let device_token = random_hex_id();
        let device_id = random_hex_id();
        let record = DeviceRecord {
            id: device_id.clone(),
            label: label.to_string(),
            created_epoch: now,
            token_hash: token_hash(&device_token),
        };
        self.accounts
            .entry(account_id.to_string())
            .or_default()
            .devices
            .push(record);
        Account {
            account_id: account_id.to_string(),
            device_token,
            device_id,
        }
    }

    fn register(&mut self, email: Option<&str>, label: &str, now: u64) -> Account {
        let account_id = random_hex_id();
        self.accounts.insert(
            account_id.clone(),
            AccountRecord {
                email: email.map(str::to_string),
                devices: Vec::new(),
            },
        );
        self.new_device(&account_id, label, now)
    }

    fn add_device(&mut self, existing_token: &str, label: &str, now: u64) -> Option<Account> {
        let account_id = self.resolve(existing_token)?.account_id;
        Some(self.new_device(&account_id, label, now))
    }

    fn resolve(&self, token: &str) -> Option<TokenIdentity> {
        let hash = token_hash(token);
        for (account_id, account) in &self.accounts {
            if let Some(device) = account.devices.iter().find(|d| d.token_hash == hash) {
                return Some(TokenIdentity {
                    account_id: account_id.clone(),
                    device_id: device.id.clone(),
                });
            }
        }
        None
    }

    fn list_devices(&self, account_id: &str) -> Vec<DeviceInfo> {
        self.accounts
            .get(account_id)
            .map(|a| a.devices.iter().map(DeviceRecord::info).collect())
            .unwrap_or_default()
    }

    fn revoke_device(&mut self, account_id: &str, device_id: &str) -> bool {
        if let Some(account) = self.accounts.get_mut(account_id) {
            let before = account.devices.len();
            account.devices.retain(|d| d.id != device_id);
            return account.devices.len() != before;
        }
        false
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
    fn register(&self, email: Option<&str>, label: &str, now: u64) -> Result<Account, SyncError> {
        Ok(self.inner.lock().unwrap().register(email, label, now))
    }

    fn add_device(
        &self,
        existing_token: &str,
        label: &str,
        now: u64,
    ) -> Result<Option<Account>, SyncError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .add_device(existing_token, label, now))
    }

    fn resolve_token(&self, token: &str) -> Result<Option<TokenIdentity>, SyncError> {
        Ok(self.inner.lock().unwrap().resolve(token))
    }

    fn list_devices(&self, account_id: &str) -> Result<Vec<DeviceInfo>, SyncError> {
        Ok(self.inner.lock().unwrap().list_devices(account_id))
    }

    fn revoke_device(&self, account_id: &str, device_id: &str) -> Result<bool, SyncError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .revoke_device(account_id, device_id))
    }
}

/// Filesystem-backed registry: the whole [`Registry`] persisted as a single
/// `accounts.json` under `dir`. A process mutex serializes read-modify-write.
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
    fn register(&self, email: Option<&str>, label: &str, now: u64) -> Result<Account, SyncError> {
        let _lock = self.guard.lock().unwrap();
        let mut registry = self.read()?;
        let account = registry.register(email, label, now);
        self.write(&registry)?;
        Ok(account)
    }

    fn add_device(
        &self,
        existing_token: &str,
        label: &str,
        now: u64,
    ) -> Result<Option<Account>, SyncError> {
        let _lock = self.guard.lock().unwrap();
        let mut registry = self.read()?;
        match registry.add_device(existing_token, label, now) {
            Some(account) => {
                self.write(&registry)?;
                Ok(Some(account))
            }
            None => Ok(None),
        }
    }

    fn resolve_token(&self, token: &str) -> Result<Option<TokenIdentity>, SyncError> {
        let _lock = self.guard.lock().unwrap();
        Ok(self.read()?.resolve(token))
    }

    fn list_devices(&self, account_id: &str) -> Result<Vec<DeviceInfo>, SyncError> {
        let _lock = self.guard.lock().unwrap();
        Ok(self.read()?.list_devices(account_id))
    }

    fn revoke_device(&self, account_id: &str, device_id: &str) -> Result<bool, SyncError> {
        let _lock = self.guard.lock().unwrap();
        let mut registry = self.read()?;
        let revoked = registry.revoke_device(account_id, device_id);
        if revoked {
            self.write(&registry)?;
        }
        Ok(revoked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account_suite(store: &dyn AccountStore) {
        // Register issues a token resolving to the new account + a device.
        let alice = store
            .register(Some("alice@example.com"), "Laptop", 100)
            .unwrap();
        let id = store.resolve_token(&alice.device_token).unwrap().unwrap();
        assert_eq!(id.account_id, alice.account_id);
        assert_eq!(id.device_id, alice.device_id);

        // add_device issues a SECOND token on the SAME account, a new device.
        let phone = store
            .add_device(&alice.device_token, "Phone", 200)
            .unwrap()
            .unwrap();
        assert_ne!(phone.device_token, alice.device_token);
        assert_eq!(phone.account_id, alice.account_id);
        assert_ne!(phone.device_id, alice.device_id);

        // Two devices listed.
        let devices = store.list_devices(&alice.account_id).unwrap();
        assert_eq!(devices.len(), 2);
        assert!(devices.iter().any(|d| d.label == "Laptop"));
        assert!(devices.iter().any(|d| d.label == "Phone"));

        // Revoke the phone: its token stops resolving, the laptop still works.
        assert!(store
            .revoke_device(&alice.account_id, &phone.device_id)
            .unwrap());
        assert!(store.resolve_token(&phone.device_token).unwrap().is_none());
        assert!(store.resolve_token(&alice.device_token).unwrap().is_some());
        assert_eq!(store.list_devices(&alice.account_id).unwrap().len(), 1);
        // Revoking an unknown device id is a no-op.
        assert!(!store.revoke_device(&alice.account_id, "nope").unwrap());

        // Unknown token resolves to None; add_device on it is None.
        assert!(store.resolve_token("deadbeef").unwrap().is_none());
        assert!(store.add_device("deadbeef", "x", 1).unwrap().is_none());
    }

    #[test]
    fn memory_store_full_lifecycle() {
        account_suite(&MemoryAccountStore::new());
    }

    #[test]
    fn file_store_full_lifecycle() {
        let dir = std::env::temp_dir().join(format!("proctor-accounts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        account_suite(&FileAccountStore::new(&dir));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tokens_are_stored_hashed_not_in_the_clear() {
        let dir = std::env::temp_dir().join(format!("proctor-acct-hash-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = FileAccountStore::new(&dir);
        let acct = store.register(None, "Laptop", 1).unwrap();
        let on_disk = std::fs::read_to_string(dir.join("accounts.json")).unwrap();
        // The plaintext token must NOT appear on disk — only its SHA-256 hash.
        assert!(!on_disk.contains(&acct.device_token));
        assert!(on_disk.contains(&token_hash(&acct.device_token)));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ids_are_128_bit_hex_and_hash_is_256_bit() {
        assert_eq!(random_hex_id().len(), 32);
        assert_eq!(token_hash("x").len(), 64);
    }
}
