//! Watchtower — a domain service that analyses the vault for weak and reused
//! passwords. Pure over the entry aggregate; no I/O.

use crate::domain::{Content, Entry};
use std::collections::HashMap;

/// A weak/reused/at-risk finding for the security dashboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Issue {
    /// Password below the strength threshold (id, estimated bits).
    Weak(String, u32),
    /// Password reused across multiple logins (the ids sharing it).
    Reused(Vec<String>),
    /// Login has 2FA available but no TOTP stored.
    Missing2fa(String),
}

/// Crude password-strength estimate in bits (character-space × length).
pub fn strength_bits(password: &str) -> u32 {
    if password.is_empty() {
        return 0;
    }
    let mut space = 0u32;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        space += 26;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        space += 26;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        space += 10;
    }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        space += 32;
    }
    let per_char = (space.max(1) as f64).log2();
    (per_char * password.chars().count() as f64) as u32
}

/// Analyze the vault for weak and reused passwords (Watchtower).
pub fn watchtower(entries: &[Entry]) -> Vec<Issue> {
    const WEAK_BELOW_BITS: u32 = 60;
    let mut issues = Vec::new();
    let mut by_password: HashMap<&str, Vec<String>> = HashMap::new();

    for e in entries {
        if let Content::Login(l) = &e.content {
            if !l.password.is_empty() {
                let bits = strength_bits(&l.password);
                if bits < WEAK_BELOW_BITS {
                    issues.push(Issue::Weak(e.id.clone(), bits));
                }
                by_password
                    .entry(l.password.as_str())
                    .or_default()
                    .push(e.id.clone());
            }
        }
    }
    for (_pw, mut ids) in by_password {
        if ids.len() > 1 {
            ids.sort();
            issues.push(Issue::Reused(ids));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<Entry> {
        vec![
            Entry::login("e1", "GitHub", "octo", "S7r0ng!Pass#word_2026"),
            Entry::login("e2", "Bank", "me", "hunter2"), // weak
            Entry::login("e3", "Netflix", "me", "hunter2"), // reused with e2
        ]
    }

    #[test]
    fn flags_weak_and_reused() {
        let issues = watchtower(&sample());
        assert!(issues
            .iter()
            .any(|i| matches!(i, Issue::Weak(id, _) if id == "e2")));
        assert!(issues.iter().any(
            |i| matches!(i, Issue::Reused(ids) if ids == &["e2".to_string(), "e3".to_string()])
        ));
        assert!(!issues
            .iter()
            .any(|i| matches!(i, Issue::Weak(id, _) if id == "e1")));
    }

    #[test]
    fn strength_increases_with_complexity() {
        assert!(strength_bits("hunter2") < strength_bits("S7r0ng!Pass#word_2026"));
    }
}
