//! RFC 8693 OAuth 2.0 Token Exchange — the *protocol* minter that collapses
//! cloud minting to one integration. Present a held "subject token" (an OIDC
//! identity / JWT) to an STS token endpoint and receive a short-lived scoped
//! access token in return. This is the mechanism behind OIDC Workload Identity
//! Federation (GCP WIF, generic STS); AWS `AssumeRoleWithWebIdentity` is a close
//! variant. One minter, any conforming STS — see ADR-0002.
//!
//! HTTP is an injected trait so the flow is tested offline; the real reqwest
//! impl lives behind the `net` feature.

use crate::{MintError, MintScope, MintedToken, Minter};
use std::time::{Duration, SystemTime};

const GRANT_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const TOKEN_TYPE_ACCESS: &str = "urn:ietf:params:oauth:token-type:access_token";
const DEFAULT_SUBJECT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";

/// Performs the form-encoded POST to the STS token endpoint.
#[async_trait::async_trait]
pub trait FormHttp: Send + Sync {
    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
    ) -> Result<serde_json::Value, MintError>;
}

/// Mints short-lived tokens via RFC 8693 token exchange against `token_endpoint`.
pub struct TokenExchangeMinter<H: FormHttp> {
    pub token_endpoint: String,
    pub audience: Option<String>,
    pub scope: Option<String>,
    pub subject_token_type: String,
    pub http: H,
}

impl<H: FormHttp> TokenExchangeMinter<H> {
    pub fn new(token_endpoint: impl Into<String>, http: H) -> Self {
        TokenExchangeMinter {
            token_endpoint: token_endpoint.into(),
            audience: None,
            scope: None,
            subject_token_type: DEFAULT_SUBJECT_TOKEN_TYPE.to_string(),
            http,
        }
    }
}

/// Build the RFC 8693 request form. `subject_token` is the held identity.
pub fn build_exchange_form(
    subject_token: &str,
    subject_token_type: &str,
    audience: &Option<String>,
    scope: &Option<String>,
) -> Vec<(String, String)> {
    let mut form = vec![
        ("grant_type".to_string(), GRANT_TOKEN_EXCHANGE.to_string()),
        ("subject_token".to_string(), subject_token.to_string()),
        ("subject_token_type".to_string(), subject_token_type.to_string()),
        ("requested_token_type".to_string(), TOKEN_TYPE_ACCESS.to_string()),
    ];
    if let Some(a) = audience {
        form.push(("audience".to_string(), a.clone()));
    }
    if let Some(s) = scope {
        form.push(("scope".to_string(), s.clone()));
    }
    form
}

#[async_trait::async_trait]
impl<H: FormHttp> Minter for TokenExchangeMinter<H> {
    async fn mint(
        &self,
        _item_id: &str,
        base_secret: &str, // the subject token (OIDC identity / JWT)
        scope: &MintScope,
    ) -> Result<MintedToken, MintError> {
        let effective_scope = self
            .scope
            .clone()
            .or_else(|| (!scope.permissions.is_empty()).then(|| scope.describe()));
        let form = build_exchange_form(
            base_secret,
            &self.subject_token_type,
            &self.audience,
            &effective_scope,
        );
        let resp = self.http.post_form(&self.token_endpoint, &form).await?;
        let access = resp
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MintError::Parse("token-exchange response missing access_token".into()))?;
        let expires = resp.get("expires_in").and_then(|v| v.as_u64()).unwrap_or(600);
        Ok(MintedToken::new(
            access.to_string(),
            SystemTime::now() + Duration::from_secs(expires),
            None,
            effective_scope.unwrap_or_else(|| scope.describe()),
            "token-exchange".to_string(),
        ))
    }

    fn provider(&self) -> &'static str {
        "token-exchange"
    }
}

#[cfg(feature = "net")]
pub struct ReqwestFormHttp {
    client: reqwest::Client,
}

#[cfg(feature = "net")]
impl ReqwestFormHttp {
    pub fn new() -> Self {
        ReqwestFormHttp { client: reqwest::Client::new() }
    }
}

#[cfg(feature = "net")]
impl Default for ReqwestFormHttp {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "net")]
#[async_trait::async_trait]
impl FormHttp for ReqwestFormHttp {
    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
    ) -> Result<serde_json::Value, MintError> {
        let resp = self
            .client
            .post(url)
            .form(form)
            .send()
            .await
            .map_err(|e| MintError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(MintError::Provider(format!("STS returned {}", resp.status())));
        }
        resp.json().await.map_err(|e| MintError::Parse(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockFormHttp {
        response: serde_json::Value,
    }
    #[async_trait::async_trait]
    impl FormHttp for MockFormHttp {
        async fn post_form(
            &self,
            _url: &str,
            form: &[(String, String)],
        ) -> Result<serde_json::Value, MintError> {
            // Confirm we shaped a spec-compliant exchange request.
            let get = |k: &str| form.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str());
            assert_eq!(get("grant_type"), Some(GRANT_TOKEN_EXCHANGE));
            assert_eq!(get("subject_token"), Some("held-oidc-jwt"));
            Ok(self.response.clone())
        }
    }

    #[test]
    fn form_has_required_rfc8693_params() {
        let f = build_exchange_form("tok", DEFAULT_SUBJECT_TOKEN_TYPE, &Some("aud".into()), &Some("s".into()));
        let has = |k: &str| f.iter().any(|(a, _)| a == k);
        assert!(has("grant_type") && has("subject_token") && has("audience") && has("scope"));
    }

    #[tokio::test]
    async fn exchanges_identity_for_short_lived_token() {
        let minter = TokenExchangeMinter::new(
            "https://sts.example.com/token",
            MockFormHttp {
                response: serde_json::json!({ "access_token": "st_shortlived", "expires_in": 600, "token_type": "Bearer" }),
            },
        );
        let t = minter.mint("itm", "held-oidc-jwt", &MintScope::read_only()).await.unwrap();
        assert_eq!(t.provider, "token-exchange");
        assert_eq!(t.expose(), "st_shortlived");
        assert!(t.is_valid(SystemTime::now()));
        assert!(!t.is_valid(SystemTime::now() + Duration::from_secs(601)));
        assert!(!t.masked().contains("st_shortlived"));
    }
}
