//! Proctor credential minting — the "mint, don't inject" primitive.
//!
//! Instead of handing an agent a durable secret, the broker asks a [`Minter`] to
//! exchange it for a **short-lived, narrowly-scoped** token. A leaked minted
//! token expires in minutes and can only touch what it was scoped to, so the
//! blast radius is small by construction.
//!
//! The minted token's value is kept in a zeroizing wrapper and must **never** be
//! returned to a model/agent context — only to the local executor that performs
//! the action. See `MintedToken::expose` vs `MintedToken::masked`.

pub mod exec;
pub mod github;

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum MintError {
    #[error("signing failed: {0}")]
    Signing(String),
    #[error("http error: {0}")]
    Http(String),
    #[error("provider error: {0}")]
    Provider(String),
    #[error("parse error: {0}")]
    Parse(String),
}

/// What a minted token is allowed to do. Provider-agnostic; providers map these
/// to their own scoping (e.g. GitHub permissions + repositories).
#[derive(Clone, Debug, Default)]
pub struct MintScope {
    /// e.g. {"contents":"read","pull_requests":"write"}
    pub permissions: BTreeMap<String, String>,
    /// Optional resource names to narrow to (e.g. repositories).
    pub resources: Vec<String>,
}

impl MintScope {
    pub fn read_only() -> Self {
        let mut permissions = BTreeMap::new();
        permissions.insert("contents".to_string(), "read".to_string());
        MintScope {
            permissions,
            resources: Vec::new(),
        }
    }

    pub fn describe(&self) -> String {
        let perms = self
            .permissions
            .iter()
            .map(|(k, v)| format!("{k}:{v}"))
            .collect::<Vec<_>>()
            .join(",");
        if self.resources.is_empty() {
            format!("[{perms}]")
        } else {
            format!("[{perms}] on {}", self.resources.join(","))
        }
    }
}

/// A freshly minted, short-lived credential. Its value is secret.
pub struct MintedToken {
    value: Zeroizing<String>,
    /// Our conservative local view of expiry (providers enforce their own).
    pub expires_at: SystemTime,
    /// The provider's authoritative expiry string, if any.
    pub provider_expires_at: Option<String>,
    pub scope_desc: String,
    pub provider: String,
}

impl MintedToken {
    pub fn new(
        value: String,
        expires_at: SystemTime,
        provider_expires_at: Option<String>,
        scope_desc: String,
        provider: String,
    ) -> Self {
        MintedToken {
            value: Zeroizing::new(value),
            expires_at,
            provider_expires_at,
            scope_desc,
            provider,
        }
    }

    /// The raw token value — for the LOCAL executor that performs the action.
    /// NEVER return this to a model/agent context.
    pub fn expose(&self) -> &str {
        &self.value
    }

    /// A safe, non-secret representation for logs and model-facing responses.
    pub fn masked(&self) -> String {
        let n = self.value.len();
        let head: String = self.value.chars().take(3).collect();
        format!("{head}…(masked, {n} chars)")
    }

    pub fn is_valid(&self, now: SystemTime) -> bool {
        now < self.expires_at
    }
}

/// A provider that mints short-lived scoped tokens from a durable base secret.
#[async_trait::async_trait]
pub trait Minter: Send + Sync {
    /// `base_secret` is the durable secret from the vault (e.g. a GitHub App
    /// private key). Returns a scoped, short-lived token — never the base secret.
    async fn mint(
        &self,
        item_id: &str,
        base_secret: &str,
        scope: &MintScope,
    ) -> Result<MintedToken, MintError>;

    fn provider(&self) -> &'static str;
}

/// A deterministic, offline minter for tests and demos. Returns a fake but
/// well-shaped short-lived token.
pub struct MockMinter;

#[async_trait::async_trait]
impl Minter for MockMinter {
    async fn mint(
        &self,
        item_id: &str,
        _base_secret: &str,
        scope: &MintScope,
    ) -> Result<MintedToken, MintError> {
        Ok(MintedToken::new(
            format!("mock_{item_id}_ephemeral_token"),
            SystemTime::now() + Duration::from_secs(600),
            None,
            scope.describe(),
            "mock".to_string(),
        ))
    }

    fn provider(&self) -> &'static str {
        "mock"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_minter_produces_scoped_short_lived_token() {
        let scope = MintScope::read_only();
        let t = MockMinter.mint("itm_github", "unused-base-secret", &scope).await.unwrap();
        assert!(t.is_valid(SystemTime::now()));
        assert!(!t.is_valid(SystemTime::now() + Duration::from_secs(601)));
        assert_eq!(t.provider, "mock");
        assert!(t.expose().contains("itm_github"));
        // masked() never reveals the whole value.
        assert!(!t.masked().contains("ephemeral_token"));
    }

    #[test]
    fn scope_describe_is_readable() {
        let mut s = MintScope::read_only();
        s.resources.push("octo/repo".into());
        let d = s.describe();
        assert!(d.contains("contents:read"));
        assert!(d.contains("octo/repo"));
    }
}
