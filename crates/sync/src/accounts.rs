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
//! Tokens may optionally **expire** (a `ttl_seconds` at mint time sets
//! `expires_epoch = now + ttl`; omit it and the token never expires — the
//! backward-compatible default). An expired token no longer authenticates:
//! [`resolve_token`] takes the current time and returns `None` past expiry.
//! A token can also be **rotated** ([`rotate_token`]) — the same device keeps
//! its id, label, and expiry but gets a fresh secret, so the old one stops
//! resolving (compromised-token recovery without re-pairing the device).
//!
//! [`resolve_token`]: AccountStore::resolve_token
//! [`rotate_token`]: AccountStore::rotate_token
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
    /// When this device's token expires (`None` = never expires).
    pub expires_epoch: Option<u64>,
}

/// An account's subscription plan — the entitlements plane. `Free` is the default
/// (self-host and the free managed tier); `Individual` and `Family` are the paid
/// managed tiers. The billing system (Stripe webhook) is the source of truth and
/// updates this via [`AccountStore::set_plan`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Plan {
    /// Self-host, or the free managed tier: capped devices, no family sharing.
    #[default]
    Free,
    /// Paid: unlimited devices + the AI credential broker.
    Individual,
    /// Paid: everything, plus family sharing.
    Family,
}

impl Plan {
    /// The canonical lowercase name (stored in Postgres / `accounts.json`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Plan::Free => "free",
            Plan::Individual => "individual",
            Plan::Family => "family",
        }
    }

    /// Parse a stored plan name; anything unrecognized falls back to `Free`.
    pub fn parse(s: &str) -> Plan {
        match s.trim().to_ascii_lowercase().as_str() {
            "individual" => Plan::Individual,
            "family" => Plan::Family,
            _ => Plan::Free,
        }
    }

    /// Whether this plan may use family sharing (paid Family only).
    pub fn can_share(&self) -> bool {
        matches!(self, Plan::Family)
    }

    /// Max devices allowed, or `None` for unlimited. Free is capped; paid is not.
    pub fn device_limit(&self) -> Option<usize> {
        match self {
            Plan::Free => Some(2),
            Plan::Individual | Plan::Family => None,
        }
    }
}

/// The driven port for accounts, per-device tokens, and device management.
pub trait AccountStore {
    /// Register a new account (optional contact email) with its first device
    /// (`label`, created at `now`). `ttl_seconds` sets an optional token
    /// lifetime (`Some(ttl)` → expires at `now + ttl`; `None` → never expires).
    /// Returns the account id, one-time token, and device id.
    fn register(
        &self,
        email: Option<&str>,
        label: &str,
        now: u64,
        ttl_seconds: Option<u64>,
    ) -> Result<Account, SyncError>;

    /// Mint an additional device for the account that `existing_token` belongs
    /// to. `ttl_seconds` sets the new token's optional lifetime (see
    /// [`register`]). `None` if the presented token is unknown or expired.
    ///
    /// [`register`]: AccountStore::register
    fn add_device(
        &self,
        existing_token: &str,
        label: &str,
        now: u64,
        ttl_seconds: Option<u64>,
    ) -> Result<Option<Account>, SyncError>;

    /// Resolve a device token to its account + device, or `None` if unknown,
    /// revoked, or **expired** as of `now`.
    fn resolve_token(&self, token: &str, now: u64) -> Result<Option<TokenIdentity>, SyncError>;

    /// Rotate a device's token: mint a fresh secret for the SAME device (same
    /// id, label, and expiry), so `old_token` stops resolving. Returns the new
    /// [`Account`] (one-time token + unchanged device id), or `None` if
    /// `old_token` is unknown or already expired as of `now`.
    fn rotate_token(&self, old_token: &str, now: u64) -> Result<Option<Account>, SyncError>;

    /// List an account's devices (no secrets).
    fn list_devices(&self, account_id: &str) -> Result<Vec<DeviceInfo>, SyncError>;

    /// Revoke a device (cut off a lost/stolen device's token). Returns whether a
    /// matching device existed.
    fn revoke_device(&self, account_id: &str, device_id: &str) -> Result<bool, SyncError>;

    /// The account's current plan (defaults to [`Plan::Free`] for an unknown
    /// account). Read by the server to enforce entitlements.
    fn get_plan(&self, account_id: &str) -> Result<Plan, SyncError>;

    /// Set the account's plan (called by the billing webhook). Returns `false` if
    /// the account does not exist.
    fn set_plan(&self, account_id: &str, plan: Plan) -> Result<bool, SyncError>;

    /// Erase the account and **every** device it owns — the identity half of
    /// account deletion (GDPR Art. 17 right to erasure). Returns whether an
    /// account actually existed; idempotent, so deleting an already-deleted
    /// account is `Ok(false)`.
    ///
    /// This is the one operation that must leave nothing: a surviving device row
    /// is a live bearer token for an account that is supposed to be gone, which
    /// is worse than not having offered deletion at all. [`revoke_device`] is
    /// therefore not a building block here — dropping devices one by one leaves a
    /// window in which some are gone and some still authenticate.
    ///
    /// The vault blob ([`SyncStore::delete`]) and group membership
    /// ([`ShareGroupStore::erase_account`]) are separate ports and are the
    /// caller's responsibility to erase as well.
    ///
    /// [`revoke_device`]: AccountStore::revoke_device
    /// [`SyncStore::delete`]: crate::SyncStore::delete
    /// [`ShareGroupStore::erase_account`]: crate::ShareGroupStore::erase_account
    fn delete_account(&self, account_id: &str) -> Result<bool, SyncError>;
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

/// A stored device: its id, label, creation time, optional token expiry, and the
/// *hash* of its token.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct DeviceRecord {
    id: String,
    label: String,
    created_epoch: u64,
    token_hash: String,
    /// Absolute epoch at which the token expires; `None` = never expires.
    /// `#[serde(default)]` keeps pre-expiry `accounts.json` files loadable.
    #[serde(default)]
    expires_epoch: Option<u64>,
}

impl DeviceRecord {
    fn info(&self) -> DeviceInfo {
        DeviceInfo {
            id: self.id.clone(),
            label: self.label.clone(),
            created_epoch: self.created_epoch,
            expires_epoch: self.expires_epoch,
        }
    }

    /// Whether this device's token is expired as of `now` (never, if no expiry).
    fn is_expired(&self, now: u64) -> bool {
        self.expires_epoch.is_some_and(|exp| exp < now)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct AccountRecord {
    email: Option<String>,
    devices: Vec<DeviceRecord>,
    /// Subscription plan (entitlements). `#[serde(default)]` keeps pre-plan
    /// `accounts.json` files loadable (they default to `Free`).
    #[serde(default)]
    plan: Plan,
}

/// The registry state: accounts, each holding its devices (by token hash). No
/// plaintext token and no vault data ever lives here.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Registry {
    accounts: HashMap<String, AccountRecord>,
}

impl Registry {
    fn new_device(
        &mut self,
        account_id: &str,
        label: &str,
        now: u64,
        ttl_seconds: Option<u64>,
    ) -> Account {
        let device_token = random_hex_id();
        let device_id = random_hex_id();
        let record = DeviceRecord {
            id: device_id.clone(),
            label: label.to_string(),
            created_epoch: now,
            token_hash: token_hash(&device_token),
            expires_epoch: ttl_seconds.map(|ttl| now.saturating_add(ttl)),
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

    fn register(
        &mut self,
        email: Option<&str>,
        label: &str,
        now: u64,
        ttl_seconds: Option<u64>,
    ) -> Account {
        let account_id = random_hex_id();
        self.accounts.insert(
            account_id.clone(),
            AccountRecord {
                email: email.map(str::to_string),
                devices: Vec::new(),
                plan: Plan::Free,
            },
        );
        self.new_device(&account_id, label, now, ttl_seconds)
    }

    fn add_device(
        &mut self,
        existing_token: &str,
        label: &str,
        now: u64,
        ttl_seconds: Option<u64>,
    ) -> Option<Account> {
        let account_id = self.resolve(existing_token, now)?.account_id;
        Some(self.new_device(&account_id, label, now, ttl_seconds))
    }

    fn resolve(&self, token: &str, now: u64) -> Option<TokenIdentity> {
        let hash = token_hash(token);
        for (account_id, account) in &self.accounts {
            if let Some(device) = account
                .devices
                .iter()
                .find(|d| d.token_hash == hash && !d.is_expired(now))
            {
                return Some(TokenIdentity {
                    account_id: account_id.clone(),
                    device_id: device.id.clone(),
                });
            }
        }
        None
    }

    /// Rotate the token of the device that `old_token` currently belongs to:
    /// replace its hash with a fresh secret, preserving id/label/expiry. `None`
    /// if `old_token` is unknown or already expired as of `now`.
    fn rotate(&mut self, old_token: &str, now: u64) -> Option<Account> {
        let hash = token_hash(old_token);
        for (account_id, account) in self.accounts.iter_mut() {
            if let Some(device) = account
                .devices
                .iter_mut()
                .find(|d| d.token_hash == hash && !d.is_expired(now))
            {
                let device_token = random_hex_id();
                device.token_hash = token_hash(&device_token);
                return Some(Account {
                    account_id: account_id.clone(),
                    device_token,
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

    fn get_plan(&self, account_id: &str) -> Plan {
        self.accounts
            .get(account_id)
            .map(|a| a.plan)
            .unwrap_or_default()
    }

    /// Drop the account record. Devices are stored inside it, so removing the
    /// entry takes every device and token hash with it — there is no second
    /// place a token could survive.
    fn delete_account(&mut self, account_id: &str) -> bool {
        self.accounts.remove(account_id).is_some()
    }

    fn set_plan(&mut self, account_id: &str, plan: Plan) -> bool {
        match self.accounts.get_mut(account_id) {
            Some(account) => {
                account.plan = plan;
                true
            }
            None => false,
        }
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
    fn register(
        &self,
        email: Option<&str>,
        label: &str,
        now: u64,
        ttl_seconds: Option<u64>,
    ) -> Result<Account, SyncError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .register(email, label, now, ttl_seconds))
    }

    fn add_device(
        &self,
        existing_token: &str,
        label: &str,
        now: u64,
        ttl_seconds: Option<u64>,
    ) -> Result<Option<Account>, SyncError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .add_device(existing_token, label, now, ttl_seconds))
    }

    fn resolve_token(&self, token: &str, now: u64) -> Result<Option<TokenIdentity>, SyncError> {
        Ok(self.inner.lock().unwrap().resolve(token, now))
    }

    fn rotate_token(&self, old_token: &str, now: u64) -> Result<Option<Account>, SyncError> {
        Ok(self.inner.lock().unwrap().rotate(old_token, now))
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

    fn get_plan(&self, account_id: &str) -> Result<Plan, SyncError> {
        Ok(self.inner.lock().unwrap().get_plan(account_id))
    }

    fn set_plan(&self, account_id: &str, plan: Plan) -> Result<bool, SyncError> {
        Ok(self.inner.lock().unwrap().set_plan(account_id, plan))
    }

    fn delete_account(&self, account_id: &str) -> Result<bool, SyncError> {
        Ok(self.inner.lock().unwrap().delete_account(account_id))
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
    fn register(
        &self,
        email: Option<&str>,
        label: &str,
        now: u64,
        ttl_seconds: Option<u64>,
    ) -> Result<Account, SyncError> {
        let _lock = self.guard.lock().unwrap();
        let mut registry = self.read()?;
        let account = registry.register(email, label, now, ttl_seconds);
        self.write(&registry)?;
        Ok(account)
    }

    fn add_device(
        &self,
        existing_token: &str,
        label: &str,
        now: u64,
        ttl_seconds: Option<u64>,
    ) -> Result<Option<Account>, SyncError> {
        let _lock = self.guard.lock().unwrap();
        let mut registry = self.read()?;
        match registry.add_device(existing_token, label, now, ttl_seconds) {
            Some(account) => {
                self.write(&registry)?;
                Ok(Some(account))
            }
            None => Ok(None),
        }
    }

    fn resolve_token(&self, token: &str, now: u64) -> Result<Option<TokenIdentity>, SyncError> {
        let _lock = self.guard.lock().unwrap();
        Ok(self.read()?.resolve(token, now))
    }

    fn rotate_token(&self, old_token: &str, now: u64) -> Result<Option<Account>, SyncError> {
        let _lock = self.guard.lock().unwrap();
        let mut registry = self.read()?;
        match registry.rotate(old_token, now) {
            Some(account) => {
                self.write(&registry)?;
                Ok(Some(account))
            }
            None => Ok(None),
        }
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

    fn get_plan(&self, account_id: &str) -> Result<Plan, SyncError> {
        let _lock = self.guard.lock().unwrap();
        Ok(self.read()?.get_plan(account_id))
    }

    fn set_plan(&self, account_id: &str, plan: Plan) -> Result<bool, SyncError> {
        let _lock = self.guard.lock().unwrap();
        let mut registry = self.read()?;
        let ok = registry.set_plan(account_id, plan);
        if ok {
            self.write(&registry)?;
        }
        Ok(ok)
    }

    fn delete_account(&self, account_id: &str) -> Result<bool, SyncError> {
        let _lock = self.guard.lock().unwrap();
        let mut registry = self.read()?;
        let deleted = registry.delete_account(account_id);
        if deleted {
            self.write(&registry)?;
        }
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account_suite(store: &dyn AccountStore) {
        // Register issues a token resolving to the new account + a device.
        let alice = store
            .register(Some("alice@example.com"), "Laptop", 100, None)
            .unwrap();
        let id = store
            .resolve_token(&alice.device_token, 100)
            .unwrap()
            .unwrap();
        assert_eq!(id.account_id, alice.account_id);
        assert_eq!(id.device_id, alice.device_id);

        // add_device issues a SECOND token on the SAME account, a new device.
        let phone = store
            .add_device(&alice.device_token, "Phone", 200, None)
            .unwrap()
            .unwrap();
        assert_ne!(phone.device_token, alice.device_token);
        assert_eq!(phone.account_id, alice.account_id);
        assert_ne!(phone.device_id, alice.device_id);

        // Two devices listed, both with no expiry.
        let devices = store.list_devices(&alice.account_id).unwrap();
        assert_eq!(devices.len(), 2);
        assert!(devices.iter().any(|d| d.label == "Laptop"));
        assert!(devices.iter().any(|d| d.label == "Phone"));
        assert!(devices.iter().all(|d| d.expires_epoch.is_none()));

        // Revoke the phone: its token stops resolving, the laptop still works.
        assert!(store
            .revoke_device(&alice.account_id, &phone.device_id)
            .unwrap());
        assert!(store
            .resolve_token(&phone.device_token, 300)
            .unwrap()
            .is_none());
        assert!(store
            .resolve_token(&alice.device_token, 300)
            .unwrap()
            .is_some());
        assert_eq!(store.list_devices(&alice.account_id).unwrap().len(), 1);
        // Revoking an unknown device id is a no-op.
        assert!(!store.revoke_device(&alice.account_id, "nope").unwrap());

        // Unknown token resolves to None; add_device on it is None.
        assert!(store.resolve_token("deadbeef", 300).unwrap().is_none());
        assert!(store
            .add_device("deadbeef", "x", 1, None)
            .unwrap()
            .is_none());
    }

    /// Deleting an account must take every device and token with it, and touch
    /// nothing else. Run against every adapter — a backend that leaves one device
    /// row behind has left a live bearer credential for a deleted account.
    fn delete_account_suite(store: &dyn AccountStore) {
        let doomed = store
            .register(Some("bye@example.com"), "Laptop", 100, None)
            .unwrap();
        let doomed_phone = store
            .add_device(&doomed.device_token, "Phone", 100, None)
            .unwrap()
            .unwrap();
        let survivor = store.register(None, "Laptop", 100, None).unwrap();

        assert!(store.delete_account(&doomed.account_id).unwrap());

        // EVERY device is gone, not just the one that would have asked.
        assert!(store
            .resolve_token(&doomed.device_token, 200)
            .unwrap()
            .is_none());
        assert!(store
            .resolve_token(&doomed_phone.device_token, 200)
            .unwrap()
            .is_none());
        assert!(store.list_devices(&doomed.account_id).unwrap().is_empty());
        // The account record itself is gone (set_plan finds nothing to update).
        assert!(!store.delete_account(&doomed.account_id).unwrap());
        assert!(!store.set_plan(&doomed.account_id, Plan::Family).unwrap());
        // A dead token cannot mint a fresh device to climb back in.
        assert!(store
            .add_device(&doomed.device_token, "Sneaky", 200, None)
            .unwrap()
            .is_none());

        // Blast radius: the other account is entirely unaffected.
        assert!(store
            .resolve_token(&survivor.device_token, 200)
            .unwrap()
            .is_some());
        assert_eq!(store.list_devices(&survivor.account_id).unwrap().len(), 1);
        assert!(!store.delete_account("no-such-account").unwrap());
    }

    #[test]
    fn memory_store_full_lifecycle() {
        account_suite(&MemoryAccountStore::new());
    }

    #[test]
    fn memory_store_deletes_an_account_and_all_its_devices() {
        delete_account_suite(&MemoryAccountStore::new());
    }

    #[test]
    fn file_store_deletes_an_account_and_all_its_devices() {
        let dir = std::env::temp_dir().join(format!("keyward-acct-del-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        delete_account_suite(&FileAccountStore::new(&dir));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn deleting_an_account_leaves_no_token_hash_on_disk() {
        let dir = std::env::temp_dir().join(format!("keyward-acct-scrub-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = FileAccountStore::new(&dir);
        let acct = store
            .register(Some("bye@example.com"), "Laptop", 1, None)
            .unwrap();
        let hash = token_hash(&acct.device_token);
        assert!(std::fs::read_to_string(dir.join("accounts.json"))
            .unwrap()
            .contains(&hash));

        assert!(store.delete_account(&acct.account_id).unwrap());

        // Erasure is on-disk, not merely in the lookup path: neither the account
        // id, the contact email, nor the token hash may survive in the file.
        let on_disk = std::fs::read_to_string(dir.join("accounts.json")).unwrap();
        assert!(!on_disk.contains(&hash), "token hash survived deletion");
        assert!(
            !on_disk.contains(&acct.account_id),
            "account id survived deletion"
        );
        assert!(
            !on_disk.contains("bye@example.com"),
            "contact email survived deletion"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_store_full_lifecycle() {
        let dir = std::env::temp_dir().join(format!("keyward-accounts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        account_suite(&FileAccountStore::new(&dir));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tokens_are_stored_hashed_not_in_the_clear() {
        let dir = std::env::temp_dir().join(format!("keyward-acct-hash-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = FileAccountStore::new(&dir);
        let acct = store.register(None, "Laptop", 1, None).unwrap();
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

    #[test]
    fn a_ttl_token_expires_and_stops_authenticating() {
        let store = MemoryAccountStore::new();
        // Mint at now=1000 with a 60s TTL → expires at 1060.
        let acct = store.register(None, "Laptop", 1000, Some(60)).unwrap();
        let devices = store.list_devices(&acct.account_id).unwrap();
        assert_eq!(devices[0].expires_epoch, Some(1060));

        // Before and at expiry it still resolves; strictly past expiry it does not.
        assert!(store
            .resolve_token(&acct.device_token, 1059)
            .unwrap()
            .is_some());
        assert!(store
            .resolve_token(&acct.device_token, 1060)
            .unwrap()
            .is_some());
        assert!(store
            .resolve_token(&acct.device_token, 1061)
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_no_ttl_token_never_expires() {
        let store = MemoryAccountStore::new();
        let acct = store.register(None, "Laptop", 1000, None).unwrap();
        assert!(store.list_devices(&acct.account_id).unwrap()[0]
            .expires_epoch
            .is_none());
        // Even far in the future it still authenticates.
        assert!(store
            .resolve_token(&acct.device_token, u64::MAX)
            .unwrap()
            .is_some());
    }

    #[test]
    fn an_expired_token_cannot_add_devices() {
        let store = MemoryAccountStore::new();
        let acct = store.register(None, "Laptop", 1000, Some(60)).unwrap();
        // Past expiry, add_device treats the token as unknown.
        assert!(store
            .add_device(&acct.device_token, "Phone", 2000, None)
            .unwrap()
            .is_none());
    }

    #[test]
    fn rotate_invalidates_the_old_token_and_keeps_the_same_device() {
        let store = MemoryAccountStore::new();
        let acct = store.register(None, "Laptop", 1000, Some(60)).unwrap();

        let rotated = store
            .rotate_token(&acct.device_token, 1010)
            .unwrap()
            .unwrap();
        // New secret, SAME device + account.
        assert_ne!(rotated.device_token, acct.device_token);
        assert_eq!(rotated.device_id, acct.device_id);
        assert_eq!(rotated.account_id, acct.account_id);

        // Old token no longer resolves; the new one resolves to the same device.
        assert!(store
            .resolve_token(&acct.device_token, 1010)
            .unwrap()
            .is_none());
        let id = store
            .resolve_token(&rotated.device_token, 1010)
            .unwrap()
            .unwrap();
        assert_eq!(id.device_id, acct.device_id);

        // Expiry is preserved across rotation (still 1060), and still only one device.
        let devices = store.list_devices(&acct.account_id).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].expires_epoch, Some(1060));
    }

    #[test]
    fn rotating_an_unknown_or_expired_token_returns_none() {
        let store = MemoryAccountStore::new();
        assert!(store.rotate_token("deadbeef", 1).unwrap().is_none());

        let acct = store.register(None, "Laptop", 1000, Some(60)).unwrap();
        // Past expiry, rotation is refused too.
        assert!(store
            .rotate_token(&acct.device_token, 2000)
            .unwrap()
            .is_none());
    }
}
