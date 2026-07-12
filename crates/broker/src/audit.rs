//! Append-only, hash-chained audit log. Every broker decision is recorded and
//! the chain is tamper-evident: mutating any past entry breaks `verify()`.

use serde::Serialize;
use sha2::{Digest, Sha256};

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
    /// Optional append-only sink: each entry is also written as a JSON line.
    file: Option<std::path::PathBuf>,
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn digest(seq: u64, item_id: &str, origin: &str, verb: &str, decision: &str, prev: &str) -> String {
    let mut h = Sha256::new();
    h.update(seq.to_le_bytes());
    h.update(item_id.as_bytes());
    h.update(origin.as_bytes());
    h.update(verb.as_bytes());
    h.update(decision.as_bytes());
    h.update(prev.as_bytes());
    hex(&h.finalize())
}

impl AuditLog {
    pub fn new() -> Self {
        AuditLog::default()
    }

    /// An audit log that also appends every entry to `path` as a JSON line.
    pub fn with_file(path: std::path::PathBuf) -> Self {
        AuditLog {
            entries: Vec::new(),
            file: Some(path),
        }
    }

    pub fn append(&mut self, item_id: &str, origin: &str, verb: &str, decision: &str) {
        let seq = self.entries.len() as u64;
        let prev = self
            .entries
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| GENESIS.to_string());
        let hash = digest(seq, item_id, origin, verb, decision, &prev);
        let entry = AuditEntry {
            seq,
            item_id: item_id.to_string(),
            origin: origin.to_string(),
            verb: verb.to_string(),
            decision: decision.to_string(),
            prev_hash: prev,
            hash,
        };
        if let Some(path) = &self.file {
            if let Ok(line) = serde_json::to_string(&entry) {
                use std::io::Write;
                match std::fs::OpenOptions::new().create(true).append(true).open(path) {
                    Ok(mut f) => {
                        let _ = writeln!(f, "{line}");
                    }
                    Err(e) => eprintln!("proctor: audit append failed: {e}"),
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
            let expected = digest(e.seq, &e.item_id, &e.origin, &e.verb, &e.decision, &prev);
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
