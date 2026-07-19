//! GitHub App installation-token minting — the canonical "mint a fresh,
//! narrowly-scoped, short-TTL token" flow.
//!
//! Flow: sign a short-lived RS256 JWT with the App private key → POST it to
//! `/app/installations/{id}/access_tokens` with optional `permissions` and
//! `repositories` to scope down → receive a token that GitHub expires in ~1h.
//!
//! Signing and HTTP are injected as traits so the whole orchestration is
//! testable offline with mocks. The real implementations ([`RealSigner`],
//! [`ReqwestHttp`]) live behind the `net` feature.

use crate::{MintError, MintScope, MintedToken, Minter};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_BASE_URL: &str = "https://api.github.com";
/// GitHub App JWTs may live at most 10 minutes; we use a conservative window.
const JWT_LIFETIME_SECS: u64 = 540;
const JWT_BACKDATE_SECS: u64 = 60;

/// GitHub App JWT claims.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Claims {
    pub iat: u64,
    pub exp: u64,
    pub iss: String,
}

/// Build the JWT claims for `app_id` at `now`. `iat` is backdated to tolerate
/// clock skew; `exp` stays within GitHub's 10-minute ceiling.
pub fn build_claims(app_id: &str, now: SystemTime) -> Claims {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Claims {
        iat: secs.saturating_sub(JWT_BACKDATE_SECS),
        exp: secs + JWT_LIFETIME_SECS,
        iss: app_id.to_string(),
    }
}

/// Build the installation-token request body from a scope (both fields optional).
pub fn build_token_body(scope: &MintScope) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !scope.resources.is_empty() {
        m.insert("repositories".into(), serde_json::json!(scope.resources));
    }
    if !scope.permissions.is_empty() {
        m.insert("permissions".into(), serde_json::json!(scope.permissions));
    }
    serde_json::Value::Object(m)
}

/// Signs GitHub App JWTs.
pub trait JwtSigner: Send + Sync {
    fn sign(&self, claims: &Claims, key_pem: &str) -> Result<String, MintError>;
}

/// The provider's token-endpoint response.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TokenHttpResponse {
    pub token: String,
    pub expires_at: String,
}

/// Performs the POST to the installation access-token endpoint.
#[async_trait::async_trait]
pub trait TokenHttp: Send + Sync {
    async fn post_access_token(
        &self,
        url: &str,
        jwt: &str,
        body: &serde_json::Value,
    ) -> Result<TokenHttpResponse, MintError>;
}

/// Mints GitHub App installation tokens. Generic over signer + http so it can be
/// exercised fully offline in tests.
pub struct GitHubAppMinter<S: JwtSigner, H: TokenHttp> {
    pub app_id: String,
    pub installation_id: String,
    pub base_url: String,
    pub signer: S,
    pub http: H,
}

impl<S: JwtSigner, H: TokenHttp> GitHubAppMinter<S, H> {
    pub fn new(
        app_id: impl Into<String>,
        installation_id: impl Into<String>,
        signer: S,
        http: H,
    ) -> Self {
        GitHubAppMinter {
            app_id: app_id.into(),
            installation_id: installation_id.into(),
            base_url: DEFAULT_BASE_URL.to_string(),
            signer,
            http,
        }
    }
}

#[async_trait::async_trait]
impl<S: JwtSigner, H: TokenHttp> Minter for GitHubAppMinter<S, H> {
    async fn mint(
        &self,
        _item_id: &str,
        base_secret: &str, // the GitHub App private-key PEM (from the vault)
        scope: &MintScope,
    ) -> Result<MintedToken, MintError> {
        let claims = build_claims(&self.app_id, SystemTime::now());
        let jwt = self.signer.sign(&claims, base_secret)?;
        let url = format!(
            "{}/app/installations/{}/access_tokens",
            self.base_url, self.installation_id
        );
        let body = build_token_body(scope);
        let resp = self.http.post_access_token(&url, &jwt, &body).await?;
        Ok(MintedToken::new(
            resp.token,
            // GitHub installation tokens last ~1h; keep a conservative local view
            // and carry the provider's authoritative string alongside.
            SystemTime::now() + Duration::from_secs(3600),
            Some(resp.expires_at),
            scope.describe(),
            "github".to_string(),
        ))
    }

    fn provider(&self) -> &'static str {
        "github"
    }
}

// ---------------------------------------------------------------------------
// Real implementations (behind the `net` feature).
// ---------------------------------------------------------------------------

#[cfg(feature = "net")]
pub struct RealSigner;

#[cfg(feature = "net")]
impl JwtSigner for RealSigner {
    fn sign(&self, claims: &Claims, key_pem: &str) -> Result<String, MintError> {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        let key = EncodingKey::from_rsa_pem(key_pem.as_bytes())
            .map_err(|e| MintError::Signing(e.to_string()))?;
        encode(&Header::new(Algorithm::RS256), claims, &key)
            .map_err(|e| MintError::Signing(e.to_string()))
    }
}

#[cfg(feature = "net")]
pub struct ReqwestHttp {
    client: reqwest::Client,
}

#[cfg(feature = "net")]
impl ReqwestHttp {
    pub fn new() -> Self {
        ReqwestHttp {
            client: reqwest::Client::new(),
        }
    }
}

#[cfg(feature = "net")]
impl Default for ReqwestHttp {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "net")]
#[async_trait::async_trait]
impl TokenHttp for ReqwestHttp {
    async fn post_access_token(
        &self,
        url: &str,
        jwt: &str,
        body: &serde_json::Value,
    ) -> Result<TokenHttpResponse, MintError> {
        let resp = self
            .client
            .post(url)
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "keyward")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(body)
            .send()
            .await
            .map_err(|e| MintError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(MintError::Provider(format!(
                "github returned {}",
                resp.status()
            )));
        }
        resp.json::<TokenHttpResponse>()
            .await
            .map_err(|e| MintError::Parse(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSigner;
    impl JwtSigner for MockSigner {
        fn sign(&self, _claims: &Claims, _key_pem: &str) -> Result<String, MintError> {
            Ok("mock.jwt.token".to_string())
        }
    }

    struct MockHttp {
        response: TokenHttpResponse,
    }
    #[async_trait::async_trait]
    impl TokenHttp for MockHttp {
        async fn post_access_token(
            &self,
            url: &str,
            jwt: &str,
            _body: &serde_json::Value,
        ) -> Result<TokenHttpResponse, MintError> {
            // Verify we shaped the request correctly.
            assert!(url.ends_with("/app/installations/42/access_tokens"));
            assert_eq!(jwt, "mock.jwt.token");
            Ok(self.response.clone())
        }
    }

    #[test]
    fn claims_are_within_github_bounds() {
        let now = SystemTime::now();
        let c = build_claims("app123", now);
        assert_eq!(c.iss, "app123");
        assert!(c.exp - c.iat <= 600);
        assert!(c.exp > c.iat);
    }

    #[test]
    fn token_body_maps_scope() {
        let mut scope = MintScope::read_only();
        scope.resources.push("octo/repo".into());
        let body = build_token_body(&scope);
        assert_eq!(body["permissions"]["contents"], "read");
        assert_eq!(body["repositories"][0], "octo/repo");
    }

    #[tokio::test]
    async fn github_minter_end_to_end_with_mocks() {
        let minter = GitHubAppMinter::new(
            "app123",
            "42",
            MockSigner,
            MockHttp {
                response: TokenHttpResponse {
                    token: "tk_installationtoken".into(),
                    expires_at: "2026-07-12T12:00:00Z".into(),
                },
            },
        );
        let token = minter
            .mint(
                "itm_github",
                "TEST-KEY-PLACEHOLDER\n...pem...",
                &MintScope::read_only(),
            )
            .await
            .unwrap();
        assert_eq!(token.provider, "github");
        assert_eq!(token.expose(), "tk_installationtoken");
        assert_eq!(
            token.provider_expires_at.as_deref(),
            Some("2026-07-12T12:00:00Z")
        );
        // The masked form never leaks the value.
        assert!(!token.masked().contains("installationtoken"));
    }
}
