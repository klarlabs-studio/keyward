//! Ports — the hexagonal boundaries the domain depends on but does not
//! implement. Adapters live in the outer crates: `passbook-cli` provides a
//! filesystem [`VaultRepository`] and a [`SystemClock`]; a future server or the
//! browser (via WASM + localStorage) would provide their own.

use crate::sealing::SealedVault;
use crate::PassbookError;

/// A driven port for persisting the sealed vault. The domain speaks in terms of
/// this trait; where the bytes actually live (a file, a database, cloud storage)
/// is an adapter's concern.
pub trait VaultRepository {
    /// Whether a sealed vault already exists in this store.
    fn exists(&self) -> bool;
    /// Load the sealed vault, or an error if absent/unreadable/corrupt.
    fn load(&self) -> Result<SealedVault, PassbookError>;
    /// Persist the sealed vault, replacing any existing one.
    fn save(&self, vault: &SealedVault) -> Result<(), PassbookError>;
}

/// A driven port for reading wall-clock time — injectable so the domain and its
/// tests never call `SystemTime::now()` directly.
pub trait Clock {
    /// Seconds since the Unix epoch.
    fn now_unix(&self) -> u64;
}
