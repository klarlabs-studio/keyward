//! Driven adapters for the broker's ports — the concrete, in-crate
//! implementations of [`crate::ports`]. `SystemClock` reads wall-clock time;
//! `FileAuditSink` appends the audit trail as JSON lines on disk. The broker's
//! domain depends only on the [`Clock`]/[`AuditSink`] traits — swapping time or
//! the audit destination means writing another adapter, not touching the core.
//!
//! These are the *default* adapters so the broker's public API and behaviour are
//! unchanged: [`crate::audit::AuditLog::with_file`] wires a [`FileAuditSink`]
//! internally, exactly as before.

use crate::ports::{AuditSink, Clock};
use std::path::PathBuf;
use std::time::SystemTime;

/// Wall-clock adapter for the [`Clock`] port.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Append-only, file-backed adapter for the [`AuditSink`] port. Each audit line
/// is written as its own line to `path`, created on first write.
pub struct FileAuditSink {
    path: PathBuf,
}

impl FileAuditSink {
    pub fn new(path: PathBuf) -> Self {
        FileAuditSink { path }
    }
}

impl AuditSink for FileAuditSink {
    fn append_line(&self, line: &str) -> std::io::Result<()> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{line}")?;
        Ok(())
    }
}
