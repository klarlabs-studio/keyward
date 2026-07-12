//! Secretless execution — the broker uses a minted token to *perform* an action
//! and returns only a sanitized, secret-free result. The token (and the durable
//! base secret) never reach the agent/model: the model asks for an action and
//! gets a result, not a value.
//!
//! v0.2.0 implements one real read operation (GitHub: list installation
//! repositories) plus a mock executor for offline demos/tests. HTTP GET is an
//! injected trait so the flow is fully testable offline.

use crate::MintError;

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

/// Mask a bearer token for safe display — never reveal the whole value.
pub fn mask(bearer: &str) -> String {
    let n = bearer.len();
    let head: String = bearer.chars().take(3).collect();
    format!("{head}…(masked, {n} chars)")
}

/// Performs an action using a bearer credential, returning a secret-free result.
///
/// The `bearer` is used *inside* the executor (as the Authorization credential)
/// and MUST NOT appear in the returned [`ExecResult`]. It can be either a minted
/// short-lived token or a durable token read straight from the vault — the
/// executor does not care where it came from.
#[async_trait::async_trait]
pub trait Executor: Send + Sync {
    async fn perform(&self, bearer: &str, action: &ExecAction) -> Result<ExecResult, MintError>;
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
    async fn perform(&self, bearer: &str, action: &ExecAction) -> Result<ExecResult, MintError> {
        Ok(ExecResult {
            summary: format!(
                "performed (mock) {:?} on {} using a bearer credential ({})",
                action.kind,
                action.target,
                mask(bearer)
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
    async fn perform(&self, bearer: &str, action: &ExecAction) -> Result<ExecResult, MintError> {
        match action.kind {
            ExecKind::Read => {
                let url = format!("{}/installation/repositories", self.base_url);
                // `bearer` flows to the HTTP layer, never back to the caller.
                let v = self.http.get_json(&url, bearer).await?;
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

    const BEARER: &str = "ghp_secret_token_from_vault";

    struct MockGet {
        response: serde_json::Value,
    }
    #[async_trait::async_trait]
    impl GetHttp for MockGet {
        async fn get_json(&self, url: &str, bearer: &str) -> Result<serde_json::Value, MintError> {
            assert!(url.ends_with("/installation/repositories"));
            assert_eq!(bearer, BEARER); // the credential is used internally
            Ok(self.response.clone())
        }
    }

    #[tokio::test]
    async fn github_read_returns_repos_without_leaking_the_credential() {
        let exec = GitHubExecutor::new(MockGet {
            response: serde_json::json!({
                "repositories": [ { "full_name": "octo/demo" }, { "full_name": "octo/infra" } ]
            }),
        });
        let res = exec
            .perform(BEARER, &ExecAction { kind: ExecKind::Read, target: "github.com".into() })
            .await
            .unwrap();
        assert!(res.summary.contains("2 repositories"));
        assert_eq!(res.data["repositories"][0], "octo/demo");
        // The credential must not appear anywhere in the sanitized result.
        let serialized = format!("{} {}", res.summary, res.data);
        assert!(!serialized.contains(BEARER));
    }

    #[tokio::test]
    async fn mock_executor_masks_the_credential() {
        let res = MockExecutor
            .perform(BEARER, &ExecAction { kind: ExecKind::Read, target: "github.com".into() })
            .await
            .unwrap();
        assert!(!res.summary.contains(BEARER));
    }
}
