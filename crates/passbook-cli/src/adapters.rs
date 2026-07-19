//! Driven adapters for the CLI: the concrete implementations of the domain's
//! ports. `FileVaultRepository` stores the sealed vault as JSON on disk;
//! `SystemClock` reads wall-clock time. The domain depends only on the
//! [`VaultRepository`]/[`Clock`] traits — swapping storage (a server, a keychain)
//! means writing another adapter, not touching the domain.

use keyward_passbook::{Clock, PassbookError, SealedVault, VaultRepository};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// A filesystem-backed vault store.
pub struct FileVaultRepository {
    path: PathBuf,
}

impl FileVaultRepository {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl VaultRepository for FileVaultRepository {
    fn exists(&self) -> bool {
        self.path.exists()
    }

    fn load(&self) -> Result<SealedVault, PassbookError> {
        let bytes = std::fs::read(&self.path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn save(&self, vault: &SealedVault) -> Result<(), PassbookError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let json = serde_json::to_vec_pretty(vault)?;
        std::fs::write(&self.path, json)?;
        Ok(())
    }
}

/// Wall-clock adapter for the [`Clock`] port.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}
