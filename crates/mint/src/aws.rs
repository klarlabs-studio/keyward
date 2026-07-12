//! AWS STS `AssumeRoleWithWebIdentity` — a *multi-field* protocol minter.
//!
//! Unlike RFC 8693 (single access token), AWS STS returns a credential *trio*
//! (access key id / secret / session token). This minter emits that trio as a
//! JSON object so it composes directly into a multi-field (`env_map`) provider
//! profile — closing the "minted creds can't fill multi-field profiles" gap.
//!
//! The held subject token (an OIDC web-identity JWT) is exchanged for short-lived
//! role credentials. HTTP is injected for offline tests; real reqwest behind
//! `net`. (STS speaks form-in / XML-out; we parse the four Credential fields.)

use crate::{MintError, MintScope, MintedToken, Minter};
use std::time::{Duration, SystemTime};

const STS_ACTION: &str = "AssumeRoleWithWebIdentity";
const STS_VERSION: &str = "2011-06-15";

/// Performs the form-encoded POST to STS and returns the raw (XML) body.
#[async_trait::async_trait]
pub trait RawHttp: Send + Sync {
    async fn post_form_raw(
        &self,
        url: &str,
        form: &[(String, String)],
    ) -> Result<String, MintError>;
}

pub struct AwsWebIdentityMinter<H: RawHttp> {
    pub sts_endpoint: String,
    pub role_arn: String,
    pub session_name: String,
    pub duration_secs: u64,
    pub http: H,
}

impl<H: RawHttp> AwsWebIdentityMinter<H> {
    pub fn new(role_arn: impl Into<String>, http: H) -> Self {
        AwsWebIdentityMinter {
            sts_endpoint: "https://sts.amazonaws.com".to_string(),
            role_arn: role_arn.into(),
            session_name: "proctor".to_string(),
            duration_secs: 3600,
            http,
        }
    }
}

/// The short-lived credential fields from an STS response.
struct StsCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: Option<String>,
}

/// Parse the STS XML with a real parser (namespace-agnostic on local name),
/// scoped to the `<Credentials>` element so we don't pick up stray tags.
fn parse_sts_credentials(xml: &str) -> Result<StsCredentials, MintError> {
    let doc = roxmltree::Document::parse(xml)
        .map_err(|e| MintError::Parse(format!("STS XML parse error: {e}")))?;
    let creds = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "Credentials")
        .ok_or_else(|| MintError::Parse("STS response has no <Credentials>".into()))?;
    let field = |name: &str| -> Option<String> {
        creds
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == name)
            .and_then(|n| n.text())
            .map(|s| s.to_string())
    };
    let missing = |f: &str| MintError::Parse(format!("STS Credentials missing {f}"));
    Ok(StsCredentials {
        access_key_id: field("AccessKeyId").ok_or_else(|| missing("AccessKeyId"))?,
        secret_access_key: field("SecretAccessKey").ok_or_else(|| missing("SecretAccessKey"))?,
        session_token: field("SessionToken").ok_or_else(|| missing("SessionToken"))?,
        expiration: field("Expiration"),
    })
}

#[async_trait::async_trait]
impl<H: RawHttp> Minter for AwsWebIdentityMinter<H> {
    async fn mint(
        &self,
        _item_id: &str,
        base_secret: &str, // the OIDC web-identity token
        _scope: &MintScope,
    ) -> Result<MintedToken, MintError> {
        let form = vec![
            ("Action".to_string(), STS_ACTION.to_string()),
            ("Version".to_string(), STS_VERSION.to_string()),
            ("RoleArn".to_string(), self.role_arn.clone()),
            ("RoleSessionName".to_string(), self.session_name.clone()),
            ("WebIdentityToken".to_string(), base_secret.to_string()),
            (
                "DurationSeconds".to_string(),
                self.duration_secs.to_string(),
            ),
        ];
        let xml = self.http.post_form_raw(&self.sts_endpoint, &form).await?;
        let creds = parse_sts_credentials(&xml)?;

        // Emit the trio as JSON so a multi-field (env_map) profile composes it.
        let value = serde_json::json!({
            "access_key_id": creds.access_key_id,
            "secret_access_key": creds.secret_access_key,
            "session_token": creds.session_token,
        })
        .to_string();

        Ok(MintedToken::new(
            value,
            SystemTime::now() + Duration::from_secs(self.duration_secs),
            creds.expiration,
            format!("[assume-role {}]", self.role_arn),
            "aws-sts".to_string(),
        ))
    }

    fn provider(&self) -> &'static str {
        "aws-sts"
    }
}

#[cfg(feature = "net")]
pub struct ReqwestRawHttp {
    client: reqwest::Client,
}

#[cfg(feature = "net")]
impl ReqwestRawHttp {
    pub fn new() -> Self {
        ReqwestRawHttp {
            client: reqwest::Client::new(),
        }
    }
}

#[cfg(feature = "net")]
impl Default for ReqwestRawHttp {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "net")]
#[async_trait::async_trait]
impl RawHttp for ReqwestRawHttp {
    async fn post_form_raw(
        &self,
        url: &str,
        form: &[(String, String)],
    ) -> Result<String, MintError> {
        let resp = self
            .client
            .post(url)
            .form(form)
            .send()
            .await
            .map_err(|e| MintError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(MintError::Provider(format!(
                "STS returned {}",
                resp.status()
            )));
        }
        resp.text()
            .await
            .map_err(|e| MintError::Parse(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STS_XML: &str = r#"<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>TKID_EXAMPLE</AccessKeyId><SecretAccessKey>secret/key/value</SecretAccessKey><SessionToken>FwoGZXIvYXdz_session</SessionToken><Expiration>2026-07-12T12:00:00Z</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>"#;

    struct MockRaw;
    #[async_trait::async_trait]
    impl RawHttp for MockRaw {
        async fn post_form_raw(
            &self,
            _url: &str,
            form: &[(String, String)],
        ) -> Result<String, MintError> {
            let get = |k: &str| form.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str());
            assert_eq!(get("Action"), Some(STS_ACTION));
            assert_eq!(get("WebIdentityToken"), Some("held-oidc-jwt"));
            Ok(STS_XML.to_string())
        }
    }

    #[tokio::test]
    async fn assume_role_returns_multifield_json_trio() {
        let minter = AwsWebIdentityMinter::new("arn:aws:iam::123:role/deploy", MockRaw);
        let t = minter
            .mint("itm", "held-oidc-jwt", &MintScope::read_only())
            .await
            .unwrap();
        assert_eq!(t.provider, "aws-sts");
        // The value is JSON composing into an env_map (AWS_* env vars).
        let v: serde_json::Value = serde_json::from_str(t.expose()).unwrap();
        assert_eq!(v["access_key_id"], "TKID_EXAMPLE");
        assert_eq!(v["secret_access_key"], "secret/key/value");
        assert_eq!(v["session_token"], "FwoGZXIvYXdz_session");
        assert_eq!(
            t.provider_expires_at.as_deref(),
            Some("2026-07-12T12:00:00Z")
        );
        assert!(!t.masked().contains("TKID_EXAMPLE"));
    }

    #[test]
    fn parses_namespaced_sts_xml_and_rejects_junk() {
        // Real STS responses carry a default namespace — the parser matches on
        // local name, so this still extracts the Credentials fields.
        let ns = r#"<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>AK</AccessKeyId><SecretAccessKey>SK</SecretAccessKey><SessionToken>ST</SessionToken></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>"#;
        let c = parse_sts_credentials(ns).unwrap();
        assert_eq!(c.access_key_id, "AK");
        assert_eq!(c.secret_access_key, "SK");
        assert!(c.expiration.is_none());
        // Malformed / missing-credentials XML is a clean error, not a panic.
        assert!(parse_sts_credentials("<not-xml").is_err());
        assert!(parse_sts_credentials("<Response></Response>").is_err());
    }
}
