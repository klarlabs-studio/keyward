//! Zero-knowledge sync — the Sync bounded context.
//!
//! The server stores an **opaque** sealed-vault blob per account and nothing
//! else: it never sees the master password, the device Secret Key, or the
//! decrypted entries. All it does is version the blob so a client can push its
//! latest and pull others' — a stolen server yields only ciphertext (the same
//! 2SKD promise, extended to the cloud).
//!
//! Concurrency is optimistic: a client presents the version it last saw; a push
//! succeeds only if that still matches the server, otherwise it is a [`Conflict`]
//! and the client must pull + merge before retrying.
//!
//! [`SyncStore`] is the port; adapters ([`MemoryStore`], [`FileStore`]) persist
//! the opaque blobs. The store never interprets a blob — that is the whole point.
//!
//! [`Conflict`]: SyncError::Conflict

pub mod accounts;

pub use accounts::{
    Account, AccountStore, DeviceInfo, FileAccountStore, MemoryAccountStore, TokenIdentity,
};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

/// A stored account's current sealed blob and its version.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncEnvelope {
    pub version: u64,
    /// The opaque sealed vault. The server treats this as bytes; only the client
    /// can decrypt it.
    pub blob: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("version conflict: server is at {server_version}")]
    Conflict { server_version: u64 },
    #[error("no vault for this account")]
    NotFound,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
}

/// The driven port for zero-knowledge blob storage.
pub trait SyncStore {
    /// Fetch the current envelope for `account`, or `None` if it has never pushed.
    fn get(&self, account: &str) -> Result<Option<SyncEnvelope>, SyncError>;

    /// Push a new blob. `expected_version` is the version the client last saw
    /// (`None` means "I believe the server has no vault yet"). Succeeds only if it
    /// still matches the server's current version, returning the new version;
    /// otherwise [`SyncError::Conflict`].
    fn put(
        &self,
        account: &str,
        expected_version: Option<u64>,
        blob: Vec<u8>,
    ) -> Result<u64, SyncError>;
}

/// Decide the next version from the server's current state and the client's
/// expectation — the optimistic-concurrency rule, factored out and pure.
fn next_version(current: Option<u64>, expected: Option<u64>) -> Result<u64, SyncError> {
    if expected == current {
        Ok(current.unwrap_or(0) + 1)
    } else {
        Err(SyncError::Conflict {
            server_version: current.unwrap_or(0),
        })
    }
}

/// In-memory store (tests, and a stateless dev server).
#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<HashMap<String, SyncEnvelope>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SyncStore for MemoryStore {
    fn get(&self, account: &str) -> Result<Option<SyncEnvelope>, SyncError> {
        Ok(self.inner.lock().unwrap().get(account).cloned())
    }

    fn put(
        &self,
        account: &str,
        expected_version: Option<u64>,
        blob: Vec<u8>,
    ) -> Result<u64, SyncError> {
        let mut map = self.inner.lock().unwrap();
        let current = map.get(account).map(|e| e.version);
        let version = next_version(current, expected_version)?;
        map.insert(account.to_string(), SyncEnvelope { version, blob });
        Ok(version)
    }
}

/// Filesystem store: one JSON envelope file per account under `dir`. A process
/// mutex serializes access so concurrent requests don't interleave a read-modify.
pub struct FileStore {
    dir: PathBuf,
    guard: Mutex<()>,
}

impl FileStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            guard: Mutex::new(()),
        }
    }

    /// Path of an account's envelope file. Account is sanitized to a safe base
    /// name so it cannot escape the storage directory.
    fn path(&self, account: &str) -> PathBuf {
        let safe: String = account
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.dir.join(format!("{safe}.json"))
    }

    fn read(&self, account: &str) -> Result<Option<SyncEnvelope>, SyncError> {
        let path = self.path(account);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path)?;
        Ok(Some(serde_json::from_slice(&bytes)?))
    }
}

impl SyncStore for FileStore {
    fn get(&self, account: &str) -> Result<Option<SyncEnvelope>, SyncError> {
        let _lock = self.guard.lock().unwrap();
        self.read(account)
    }

    fn put(
        &self,
        account: &str,
        expected_version: Option<u64>,
        blob: Vec<u8>,
    ) -> Result<u64, SyncError> {
        let _lock = self.guard.lock().unwrap();
        let current = self.read(account)?.map(|e| e.version);
        let version = next_version(current, expected_version)?;
        std::fs::create_dir_all(&self.dir)?;
        let env = SyncEnvelope { version, blob };
        std::fs::write(self.path(account), serde_json::to_vec(&env)?)?;
        Ok(version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_suite(store: &dyn SyncStore) {
        // Unknown account: nothing there yet.
        assert!(store.get("alice").unwrap().is_none());

        // First push expects no prior vault (None) → version 1.
        let v1 = store.put("alice", None, b"ciphertext-1".to_vec()).unwrap();
        assert_eq!(v1, 1);
        let got = store.get("alice").unwrap().unwrap();
        assert_eq!(got.version, 1);
        assert_eq!(got.blob, b"ciphertext-1");

        // Correct expected version → accepted, bumps to 2.
        let v2 = store
            .put("alice", Some(1), b"ciphertext-2".to_vec())
            .unwrap();
        assert_eq!(v2, 2);

        // Stale push (still thinks it's at v1) → Conflict reporting server=2.
        let err = store.put("alice", Some(1), b"stale".to_vec()).unwrap_err();
        assert!(matches!(err, SyncError::Conflict { server_version: 2 }));
        // The rejected blob did not land.
        assert_eq!(store.get("alice").unwrap().unwrap().blob, b"ciphertext-2");

        // A different account is independent.
        assert_eq!(store.put("bob", None, b"bob-1".to_vec()).unwrap(), 1);
    }

    #[test]
    fn memory_store_roundtrip_and_conflict() {
        roundtrip_suite(&MemoryStore::new());
    }

    #[test]
    fn file_store_roundtrip_and_conflict() {
        let dir = std::env::temp_dir().join(format!("proctor-sync-test-{}", std::process::id()));
        let store = FileStore::new(&dir);
        roundtrip_suite(&store);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn first_push_with_stale_expectation_conflicts() {
        let store = MemoryStore::new();
        // Client thinks server is at v5 but server is empty → conflict at 0.
        let err = store.put("carol", Some(5), b"x".to_vec()).unwrap_err();
        assert!(matches!(err, SyncError::Conflict { server_version: 0 }));
    }

    #[test]
    fn account_name_is_sanitized_to_a_safe_path() {
        let dir = std::env::temp_dir().join(format!("proctor-sync-safe-{}", std::process::id()));
        let store = FileStore::new(&dir);
        // A traversal-y account name must not escape the dir.
        store.put("../../etc/passwd", None, b"z".to_vec()).unwrap();
        let escaped = std::path::Path::new("/etc/passwd.json");
        assert!(!escaped.exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
