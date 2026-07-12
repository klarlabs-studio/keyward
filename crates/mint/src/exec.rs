//! Secretless execution — the broker uses a bearer credential (minted or read
//! from the vault) to *perform* an action and returns only a sanitized result.
//! The model asks for an action and gets a result, never a value.
//!
//! Reads return data; the proposable write ([`ExecKind::OpenPullRequest`])
//! produces a **reviewable artifact** (a draft PR), never a committed/merged
//! change — the runtime half of propose-not-commit.
//!
//! HTTP is an injected trait so the whole flow is testable offline; the real
//! `reqwest` client lives behind the `net` feature.

use crate::MintError;

/// What to perform. Reads are terminal; the write is deliberately a *proposal*.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecKind {
    Read,
    /// Open a pull request — a reviewable artifact, never a merge.
    OpenPullRequest,
}

pub struct ExecAction {
    pub kind: ExecKind,
    pub target: String,
    /// Operation parameters (e.g. PR owner/repo/head/base/title). May be null.
    pub params: serde_json::Value,
}

impl ExecAction {
    pub fn new(kind: ExecKind, target: impl Into<String>) -> Self {
        ExecAction { kind, target: target.into(), params: serde_json::Value::Null }
    }

    pub fn with_params(kind: ExecKind, target: impl Into<String>, params: serde_json::Value) -> Self {
        ExecAction { kind, target: target.into(), params }
    }
}

/// The sanitized outcome returned to the model. Contains no secret material.
pub struct ExecResult {
    pub summary: String,
    pub data: serde_json::Value,
}

/// Mask a bearer credential for safe display — never reveal the whole value.
pub fn mask(bearer: &str) -> String {
    let n = bearer.len();
    let head: String = bearer.chars().take(3).collect();
    format!("{head}…(masked, {n} chars)")
}

/// Performs an action using a bearer credential, returning a secret-free result.
///
/// The `bearer` is used *inside* the executor and MUST NOT appear in the result.
/// It may be a minted short-lived token or a durable token read from the vault —
/// the executor does not care which.
#[async_trait::async_trait]
pub trait Executor: Send + Sync {
    async fn perform(&self, bearer: &str, action: &ExecAction) -> Result<ExecResult, MintError>;
    fn provider(&self) -> &'static str;
}

/// Injected authenticated HTTP (so executors are testable offline).
#[async_trait::async_trait]
pub trait HttpClient: Send + Sync {
    async fn get_json(&self, url: &str, bearer: &str) -> Result<serde_json::Value, MintError>;
    async fn post_json(
        &self,
        url: &str,
        bearer: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, MintError>;
}

/// Offline executor for demos/tests. Returns canned, secret-free results and only
/// ever references the credential in masked form.
pub struct MockExecutor;

#[async_trait::async_trait]
impl Executor for MockExecutor {
    async fn perform(&self, bearer: &str, action: &ExecAction) -> Result<ExecResult, MintError> {
        match action.kind {
            ExecKind::Read => Ok(ExecResult {
                summary: format!(
                    "performed (mock) Read on {} using a bearer credential ({})",
                    action.target,
                    mask(bearer)
                ),
                data: serde_json::json!({ "mock": true, "repositories": ["octo/demo"] }),
            }),
            ExecKind::OpenPullRequest => Ok(ExecResult {
                summary: format!(
                    "opened (mock) a draft pull request on {} — a reviewable artifact, not a merge ({})",
                    action.target,
                    mask(bearer)
                ),
                data: serde_json::json!({
                    "mock": true,
                    "artifact": "pull_request",
                    "url": "https://github.com/octo/demo/pull/1",
                    "state": "open (draft, review required — not merged)"
                }),
            }),
        }
    }

    fn provider(&self) -> &'static str {
        "mock"
    }
}

/// Real GitHub executor. Reads → list installation repositories. OpenPullRequest
/// → POST a **draft** PR (reviewable artifact) from the supplied params.
pub struct GitHubExecutor<H: HttpClient> {
    pub base_url: String,
    pub http: H,
}

impl<H: HttpClient> GitHubExecutor<H> {
    pub fn new(http: H) -> Self {
        GitHubExecutor {
            base_url: "https://api.github.com".to_string(),
            http,
        }
    }
}

#[async_trait::async_trait]
impl<H: HttpClient> Executor for GitHubExecutor<H> {
    async fn perform(&self, bearer: &str, action: &ExecAction) -> Result<ExecResult, MintError> {
        match action.kind {
            ExecKind::Read => {
                let url = format!("{}/installation/repositories", self.base_url);
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
            ExecKind::OpenPullRequest => {
                let p = &action.params;
                let field = |k: &str| p.get(k).and_then(|v| v.as_str());
                let (owner, repo, head, base, title) = match (
                    field("owner"),
                    field("repo"),
                    field("head"),
                    field("base"),
                    field("title"),
                ) {
                    (Some(o), Some(r), Some(h), Some(b), Some(t)) => (o, r, h, b, t),
                    _ => {
                        return Err(MintError::Provider(
                            "pull request requires params: owner, repo, head, base, title".into(),
                        ))
                    }
                };
                let url = format!("{}/repos/{owner}/{repo}/pulls", self.base_url);
                // draft:true keeps it a reviewable artifact, never an auto-merge.
                let body = serde_json::json!({ "title": title, "head": head, "base": base, "draft": true });
                let resp = self.http.post_json(&url, bearer, &body).await?;
                let pr_url = resp.get("html_url").and_then(|v| v.as_str()).unwrap_or("(unknown)");
                Ok(ExecResult {
                    summary: format!("opened a draft pull request {pr_url} — reviewable, not merged"),
                    data: serde_json::json!({
                        "artifact": "pull_request",
                        "url": pr_url,
                        "state": "open (draft, review required — not merged)"
                    }),
                })
            }
        }
    }

    fn provider(&self) -> &'static str {
        "github"
    }
}

#[cfg(feature = "net")]
pub struct ReqwestClient {
    client: reqwest::Client,
}

#[cfg(feature = "net")]
impl ReqwestClient {
    pub fn new() -> Self {
        ReqwestClient { client: reqwest::Client::new() }
    }
}

#[cfg(feature = "net")]
impl Default for ReqwestClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "net")]
#[async_trait::async_trait]
impl HttpClient for ReqwestClient {
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

    async fn post_json(
        &self,
        url: &str,
        bearer: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, MintError> {
        let resp = self
            .client
            .post(url)
            .header("Authorization", format!("Bearer {bearer}"))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "proctor")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(body)
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

    struct MockHttp {
        get_response: serde_json::Value,
        post_response: serde_json::Value,
    }
    #[async_trait::async_trait]
    impl HttpClient for MockHttp {
        async fn get_json(&self, url: &str, bearer: &str) -> Result<serde_json::Value, MintError> {
            assert!(url.ends_with("/installation/repositories"));
            assert_eq!(bearer, BEARER);
            Ok(self.get_response.clone())
        }
        async fn post_json(
            &self,
            url: &str,
            bearer: &str,
            body: &serde_json::Value,
        ) -> Result<serde_json::Value, MintError> {
            assert!(url.contains("/pulls"));
            assert_eq!(bearer, BEARER);
            assert_eq!(body["draft"], true); // never a merge — reviewable artifact
            Ok(self.post_response.clone())
        }
    }

    fn http() -> MockHttp {
        MockHttp {
            get_response: serde_json::json!({
                "repositories": [ { "full_name": "octo/demo" }, { "full_name": "octo/infra" } ]
            }),
            post_response: serde_json::json!({ "html_url": "https://github.com/octo/demo/pull/7" }),
        }
    }

    #[tokio::test]
    async fn github_read_returns_repos_without_leaking_the_credential() {
        let exec = GitHubExecutor::new(http());
        let res = exec.perform(BEARER, &ExecAction::new(ExecKind::Read, "github.com")).await.unwrap();
        assert!(res.summary.contains("2 repositories"));
        assert_eq!(res.data["repositories"][0], "octo/demo");
        assert!(!format!("{} {}", res.summary, res.data).contains(BEARER));
    }

    #[tokio::test]
    async fn github_open_pr_creates_a_draft_artifact() {
        let exec = GitHubExecutor::new(http());
        let action = ExecAction::with_params(
            ExecKind::OpenPullRequest,
            "github.com",
            serde_json::json!({ "owner": "octo", "repo": "demo", "head": "fix", "base": "main", "title": "Fix" }),
        );
        let res = exec.perform(BEARER, &action).await.unwrap();
        assert!(res.summary.contains("draft pull request"));
        assert_eq!(res.data["url"], "https://github.com/octo/demo/pull/7");
        assert!(res.data["state"].as_str().unwrap().contains("not merged"));
        assert!(!format!("{} {}", res.summary, res.data).contains(BEARER));
    }

    #[tokio::test]
    async fn open_pr_requires_params() {
        let exec = GitHubExecutor::new(http());
        let res = exec.perform(BEARER, &ExecAction::new(ExecKind::OpenPullRequest, "github.com")).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn mock_executor_masks_the_credential() {
        let res = MockExecutor.perform(BEARER, &ExecAction::new(ExecKind::Read, "github.com")).await.unwrap();
        assert!(!res.summary.contains(BEARER));
    }
}
