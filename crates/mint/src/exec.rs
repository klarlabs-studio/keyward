//! Secretless execution — the broker uses a minted token to *perform* an action
//! and returns only a sanitized, secret-free result. The token (and the durable
//! base secret) never reach the agent/model: the model asks for an action and
//! gets a result, not a value.
//!
//! v0.2.0 implements one real read operation (GitHub: list installation
//! repositories) plus a mock executor for offline demos/tests. HTTP GET is an
//! injected trait so the flow is fully testable offline.

use crate::{MintError, MintedToken};

/// What to perform. Deliberately small; extended as real operations are added.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecKind {
    Read,
}

pub struct ExecAction {
    pub kind: ExecKind,
    pub target: String,
}

/// The sanitized outcome returned to the model. Contains no secret material.
pub struct ExecResult {
    pub summary: String,
    pub data: serde_json::Value,
}

/// Performs an action using an already-minted token, returning a secret-free result.
#[async_trait::async_trait]
pub trait Executor: Send + Sync {
    async fn perform(&self, token: &MintedToken, action: &ExecAction) -> Result<ExecResult, MintError>;
    fn provider(&self) -> &'static str;
}

/// Injected authenticated GET (so executors are testable offline).
#[async_trait::async_trait]
pub trait GetHttp: Send + Sync {
    async fn get_json(&self, url: &str, bearer: &str) -> Result<serde_json::Value, MintError>;
}

/// Offline executor for demos/tests. Returns a canned, secret-free result and
/// only ever references the token in masked form.
pub struct MockExecutor;

#[async_trait::async_trait]
impl Executor for MockExecutor {
    async fn perform(&self, token: &MintedToken, action: &ExecAction) -> Result<ExecResult, MintError> {
        Ok(ExecResult {
            summary: format!(
                "performed (mock) {:?} on {} using a minted token ({})",
                action.kind,
                action.target,
                token.masked()
            ),
            data: serde_json::json!({ "mock": true, "repositories": ["octo/demo"] }),
        })
    }

    fn provider(&self) -> &'static str {
        "mock"
    }
}

/// Real GitHub executor: uses the minted installation token to list the
/// repositories the installation can access.
pub struct GitHubExecutor<G: GetHttp> {
    pub base_url: String,
    pub http: G,
}

impl<G: GetHttp> GitHubExecutor<G> {
    pub fn new(http: G) -> Self {
        GitHubExecutor {
            base_url: "https://api.github.com".to_string(),
            http,
        }
    }
}

#[async_trait::async_trait]
impl<G: GetHttp> Executor for GitHubExecutor<G> {
    async fn perform(&self, token: &MintedToken, action: &ExecAction) -> Result<ExecResult, MintError> {
        match action.kind {
            ExecKind::Read => {
                let url = format!("{}/installation/repositories", self.base_url);
                // token.expose() flows to the HTTP layer, never to the caller.
                let v = self.http.get_json(&url, token.expose()).await?;
                let repos: Vec<String> = v
                    .get("repositories")
                    .and_then(|r| r.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.get("full_name").and_then(|n| n.as_str()).map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                Ok(ExecResult {
                    summary: format!("listed {} repositories accessible to the installation", repos.len()),
                    data: serde_json::json!({ "repositories": repos }),
                })
            }
        }
    }

    fn provider(&self) -> &'static str {
        "github"
    }
}

#[cfg(feature = "net")]
pub struct ReqwestGet {
    client: reqwest::Client,
}

#[cfg(feature = "net")]
impl ReqwestGet {
    pub fn new() -> Self {
        ReqwestGet {
            client: reqwest::Client::new(),
        }
    }
}

#[cfg(feature = "net")]
impl Default for ReqwestGet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "net")]
#[async_trait::async_trait]
impl GetHttp for ReqwestGet {
    async fn get_json(&self, url: &str, bearer: &str) -> Result<serde_json::Value, MintError> {
        let resp = self
            .client
            .get(url)
            .header("Authorization", format!("Bearer {bearer}"))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "proctor")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .map_err(|e| MintError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(MintError::Provider(format!("github returned {}", resp.status())));
        }
        resp.json().await.map_err(|e| MintError::Parse(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MintedToken;
    use std::time::{Duration, SystemTime};

    fn token() -> MintedToken {
        MintedToken::new(
            "ghs_secret_installation_token".into(),
            SystemTime::now() + Duration::from_secs(3600),
            None,
            "[contents:read]".into(),
            "github".into(),
        )
    }

    struct MockGet {
        response: serde_json::Value,
    }
    #[async_trait::async_trait]
    impl GetHttp for MockGet {
        async fn get_json(&self, url: &str, bearer: &str) -> Result<serde_json::Value, MintError> {
            assert!(url.ends_with("/installation/repositories"));
            assert_eq!(bearer, "ghs_secret_installation_token"); // token used internally
            Ok(self.response.clone())
        }
    }

    #[tokio::test]
    async fn github_read_returns_repos_without_leaking_token() {
        let exec = GitHubExecutor::new(MockGet {
            response: serde_json::json!({
                "repositories": [ { "full_name": "octo/demo" }, { "full_name": "octo/infra" } ]
            }),
        });
        let res = exec
            .perform(&token(), &ExecAction { kind: ExecKind::Read, target: "github.com".into() })
            .await
            .unwrap();
        assert!(res.summary.contains("2 repositories"));
        assert_eq!(res.data["repositories"][0], "octo/demo");
        // The token value must not appear anywhere in the sanitized result.
        let serialized = format!("{} {}", res.summary, res.data);
        assert!(!serialized.contains("ghs_secret_installation_token"));
    }

    #[tokio::test]
    async fn mock_executor_masks_the_token() {
        let res = MockExecutor
            .perform(&token(), &ExecAction { kind: ExecKind::Read, target: "github.com".into() })
            .await
            .unwrap();
        assert!(!res.summary.contains("ghs_secret_installation_token"));
    }
}
