//! Append-only, hash-chained audit log. Every broker decision is recorded and
//! the chain is tamper-evident: mutating any past entry breaks `verify()`.
//!
//! With a signing key (see [`AuditLog::with_file_signed`]), the chain is HMAC-ed
//! rather than plain-SHA256, so an attacker with only filesystem write (no key)
//! cannot forge a valid chain — tamper-*resistant*, not just tamper-evident.
//!
//! The chain construction here is domain logic; *where* each serialized line is
//! durably persisted is a driven [`AuditSink`](crate::ports::AuditSink) port.
//! The `with_file*` constructors wire the default
//! [`FileAuditSink`](crate::adapters::FileAuditSink) adapter, so the public API
//! and on-disk format are unchanged.

use crate::adapters::FileAuditSink;
use crate::ports::AuditSink;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const GENESIS: &str = "GENESIS";

#[derive(Clone, Debug, Serialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub item_id: String,
    pub origin: String,
    pub verb: String,
    pub decision: String,
    pub prev_hash: String,
    pub hash: String,
}

#[derive(Default)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
    /// Optional driven sink: each entry is also written to it as a JSON line.
    /// The default adapter is a file (see [`AuditLog::with_file`]); any
    /// [`AuditSink`] impl works.
    sink: Option<Box<dyn AuditSink>>,
    /// Set if a persistent-sink write ever failed (surfaced, not swallowed).
    write_failed: bool,
    /// Optional HMAC key: when set, the chain is signed (forgery needs the key).
    key: Option<Vec<u8>>,
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[allow(clippy::too_many_arguments)]
fn digest(
    key: Option<&[u8]>,
    seq: u64,
    item_id: &str,
    origin: &str,
    verb: &str,
    decision: &str,
    prev: &str,
) -> String {
    match key {
        // Signed chain: HMAC-SHA256 — an attacker without the key can't forge it.
        Some(k) => {
            let mut mac = HmacSha256::new_from_slice(k).expect("HMAC accepts any key length");
            mac.update(&seq.to_le_bytes());
            mac.update(item_id.as_bytes());
            mac.update(origin.as_bytes());
            mac.update(verb.as_bytes());
            mac.update(decision.as_bytes());
            mac.update(prev.as_bytes());
            hex(&mac.finalize().into_bytes())
        }
        // Unsigned chain: plain SHA-256 — tamper-evident only.
        None => {
            let mut h = Sha256::new();
            h.update(seq.to_le_bytes());
            h.update(item_id.as_bytes());
            h.update(origin.as_bytes());
            h.update(verb.as_bytes());
            h.update(decision.as_bytes());
            h.update(prev.as_bytes());
            hex(&h.finalize())
        }
    }
}

impl AuditLog {
    pub fn new() -> Self {
        AuditLog::default()
    }

    /// An audit log that also appends every entry to `path` as a JSON line,
    /// via the default [`FileAuditSink`] adapter.
    pub fn with_file(path: std::path::PathBuf) -> Self {
        AuditLog::with_sink(Box::new(FileAuditSink::new(path)), None)
    }

    /// Like [`AuditLog::with_file`], but the chain is HMAC-signed with `key` so
    /// forgery requires the key (tamper-resistant, not just tamper-evident).
    pub fn with_file_signed(path: std::path::PathBuf, key: Vec<u8>) -> Self {
        AuditLog::with_sink(Box::new(FileAuditSink::new(path)), Some(key))
    }

    /// An audit log that persists every entry through an arbitrary [`AuditSink`]
    /// adapter (a file, a socket, an object store…), optionally HMAC-signing the
    /// chain with `key`. The `with_file*` constructors are thin wrappers over
    /// this that inject the default file adapter.
    pub fn with_sink(sink: Box<dyn AuditSink>, key: Option<Vec<u8>>) -> Self {
        AuditLog {
            entries: Vec::new(),
            sink: Some(sink),
            write_failed: false,
            key,
        }
    }

    /// True if a persistent-sink write has failed (the trail on disk is
    /// incomplete). Callers should surface this on security-relevant decisions.
    pub fn write_failed(&self) -> bool {
        self.write_failed
    }

    pub fn append(&mut self, item_id: &str, origin: &str, verb: &str, decision: &str) {
        let seq = self.entries.len() as u64;
        let prev = self
            .entries
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| GENESIS.to_string());
        let hash = digest(
            self.key.as_deref(),
            seq,
            item_id,
            origin,
            verb,
            decision,
            &prev,
        );
        let entry = AuditEntry {
            seq,
            item_id: item_id.to_string(),
            origin: origin.to_string(),
            verb: verb.to_string(),
            decision: decision.to_string(),
            prev_hash: prev,
            hash,
        };
        if let Some(sink) = &self.sink {
            if let Ok(line) = serde_json::to_string(&entry) {
                if let Err(e) = sink.append_line(&line) {
                    self.write_failed = true;
                    eprintln!("proctor: audit append failed: {e}");
                }
            }
        }
        self.entries.push(entry);
    }

    /// Recompute the chain and confirm nothing was altered.
    pub fn verify(&self) -> bool {
        let mut prev = GENESIS.to_string();
        for (i, e) in self.entries.iter().enumerate() {
            if e.seq != i as u64 || e.prev_hash != prev {
                return false;
            }
            let expected = digest(
                self.key.as_deref(),
                e.seq,
                &e.item_id,
                &e.origin,
                &e.verb,
                &e.decision,
                &prev,
            );
            if expected != e.hash {
                return false;
            }
            prev = e.hash.clone();
        }
        true
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_chain_is_forgery_resistant() {
        let mut log = AuditLog::with_file_signed(
            std::env::temp_dir().join("proctor-signed-audit.jsonl"),
            b"secret-audit-key".to_vec(),
        );
        let _ = std::fs::remove_file(std::env::temp_dir().join("proctor-signed-audit.jsonl"));
        log.append("itm", "github.com", "Read", "ALLOW");
        log.append("itm", "bank.com", "MoveMoney", "STEPUP");
        assert!(log.verify());
        // Re-signing a forged entry needs the key — verifying with a DIFFERENT key fails.
        log.key = Some(b"attacker-guessed-key".to_vec());
        assert!(!log.verify(), "chain verified under the wrong key");
        let _ = std::fs::remove_file(std::env::temp_dir().join("proctor-signed-audit.jsonl"));
    }

    #[test]
    fn chain_verifies_and_detects_tampering() {
        let mut log = AuditLog::new();
        log.append("itm_a", "github.com", "Read", "ALLOW");
        log.append("itm_a", "evil.com", "Read", "DENY:origin-mismatch");
        log.append("itm_b", "bank.com", "MoveMoney", "STEPUP");
        assert!(log.verify());

        // Silently rewrite a past decision — the chain must break.
        log.entries[1].decision = "ALLOW".to_string();
        assert!(!log.verify());
    }

    #[test]
    fn file_sink_appends_json_lines() {
        let path = std::env::temp_dir().join(format!("proctor-audit-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut log = AuditLog::with_file(path.clone());
        log.append("itm_a", "github.com", "Read", "ALLOW");
        log.append("itm_a", "evil.com", "Read", "DENY");
        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"decision\":\"ALLOW\""));
        assert!(lines[1].contains("DENY"));
        let _ = std::fs::remove_file(&path);
    }
}
