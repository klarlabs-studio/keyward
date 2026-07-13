//! Ports — the hexagonal boundaries the broker's domain depends on but does not
//! implement. The broker is the domain core of the Credential Broker context
//! (capabilities, origin-binding, propose-not-commit, risk-tiered policy,
//! hash-chained audit); its *driven* dependencies live behind these traits so
//! the core never names a file or `SystemTime` directly. Adapters implementing
//! them are provided in [`crate::adapters`] (and any other host — an MCP server,
//! a CLI — is free to supply its own).
//!
//! Two driven ports:
//!
//! - [`Clock`] — wall-clock time. The broker's decisions and capability TTLs are
//!   parameterised on a `now: SystemTime` threaded in by the caller, so time is
//!   already inverted at the call boundary; [`Clock`] names that seam and
//!   [`crate::adapters::SystemClock`] is its real adapter, keeping tests and the
//!   domain free of ambient `SystemTime::now()`.
//! - [`AuditSink`] — the durable destination of the hash-chained audit trail.
//!   The chain construction (hashing / HMAC signing / tamper-evidence) is domain
//!   logic inside [`crate::audit::AuditLog`]; *where the serialized line is
//!   persisted* is an adapter's concern. [`crate::adapters::FileAuditSink`] is
//!   the append-only JSON-lines file adapter.
//!
//! Note also the ports the broker only *names* rather than owns: the **Minter**
//! (short-lived scoped tokens) and **Executor** are traits in `proctor-mint`;
//! the broker merely selects the [`crate::Primitive::Minted`] outcome and the
//! executing host wires the concrete minter. See the context map.

use std::time::SystemTime;

/// A driven port for reading wall-clock time — injectable so the broker's
/// domain and its tests never call [`SystemTime::now`] directly. Mirrors
/// Passbook's `ports::Clock`.
pub trait Clock {
    /// The current instant.
    fn now(&self) -> SystemTime;
}

/// A driven port for the durable audit sink: persist one already-serialized,
/// already-chained audit line. The hash chain itself (tamper-evidence, optional
/// HMAC signing) is domain logic in [`crate::audit::AuditLog`]; this port only
/// concerns *where* the line lands (a file, a syslog socket, an object store).
///
/// `Send + Sync` so the broker can be shared across async tasks (the MCP server
/// holds it behind a lock).
pub trait AuditSink: Send + Sync {
    /// Append one serialized audit entry (a single JSON line, without a trailing
    /// newline — the sink adds its own record separator). Errors are surfaced to
    /// the caller, which records that the on-disk trail is incomplete.
    fn append_line(&self, line: &str) -> std::io::Result<()>;
}
