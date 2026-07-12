//! proctor-mcp — the Proctor credential broker exposed as an MCP server over
//! stdio, backed by a real vault and a minting layer.
//!
//! Tools:
//!   - `list_credentials`  — secret-free item metadata
//!   - `use_credential`    — request a scoped action/handle (never plaintext).
//!                           On an allowed, mintable item it MINTS a fresh,
//!                           scoped, short-TTL token held server-side and
//!                           returns only a reference + masked view.
//!   - `audit_log`         — the tamper-evident decision trail
//!
//! Config via env:
//!   PROCTOR_VAULT / PROCTOR_MASTER      load a real vault (else demo items)
//!   PROCTOR_APPROVED_ORIGINS            csv override for the auto-approve list
//!   PROCTOR_GH_APP_ID / PROCTOR_GH_INSTALLATION_ID
//!                                       use the real GitHub App minter (else mock)
//!
//! NOTE: prototype. The minted token is held server-side and never returned to
//! the model; a follow-up execution surface (secretless "perform") is the next
//! step. Formal security review required before real use.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
    ErrorData as McpError, ServerHandler, ServiceExt,
};
use serde_json::json;
use tokio::sync::Mutex;

use proctor_broker::{Action, ActionVerb, Broker, Denied, Grant, ItemRef, Mode, Policy, Primitive};
use proctor_mint::github::{GitHubAppMinter, RealSigner, ReqwestHttp};
use proctor_mint::{MintScope, MintedToken, Minter, MockMinter};

struct AppState {
    items: Vec<ItemRef>,
    /// item_id → durable base secret. Held server-side only; never model-facing.
    secrets: HashMap<String, String>,
    broker: Broker,
    /// token_ref → minted token, held server-side for the executor.
    minted: HashMap<String, MintedToken>,
}

#[derive(Clone)]
struct ProctorServer {
    state: Arc<Mutex<AppState>>,
    minter: Arc<dyn Minter>,
    // Used by the #[tool_router]/#[tool_handler] macro machinery.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct UseCredentialArgs {
    /// The item id from `list_credentials` (e.g. "itm_github").
    item_id: String,
    /// The origin the credential will be used against (e.g. "github.com").
    origin: String,
    /// One of: Read, RunTests, FetchData, OpenPullRequest, DraftMessage,
    /// StageChange, MintReadToken, DeleteData, MoveMoney, ShipToProduction,
    /// SendCommsAsUser, RotateOrRevokeOtherCredential.
    verb: String,
    /// True if the agent is running unattended (no human present to approve).
    #[serde(default)]
    unattended: bool,
    /// Request the raw durable secret. Hard-denied by default.
    #[serde(default)]
    want_raw_secret: bool,
}

/// Which scope a minted token should carry for a given verb (v1: read-only).
fn scope_for(_verb: ActionVerb) -> MintScope {
    MintScope::read_only()
}

#[tool_router]
impl ProctorServer {
    fn with(
        items: Vec<ItemRef>,
        secrets: HashMap<String, String>,
        minter: Arc<dyn Minter>,
        approved_origins: &[String],
    ) -> Self {
        let approved: Vec<&str> = approved_origins.iter().map(|s| s.as_str()).collect();
        ProctorServer {
            state: Arc::new(Mutex::new(AppState {
                items,
                secrets,
                broker: Broker::new(Policy::with_approved_origins(&approved)),
                minted: HashMap::new(),
            })),
            minter,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "List available credentials as secret-free metadata (id, label, bound origins, mintable). Never returns secrets."
    )]
    async fn list_credentials(&self) -> Result<CallToolResult, McpError> {
        let state = self.state.lock().await;
        let list: Vec<_> = state
            .items
            .iter()
            .map(|i| {
                json!({
                    "id": i.id,
                    "label": i.label,
                    "bound_origins": i.bound_origins,
                    "mintable": i.mintable,
                })
            })
            .collect();
        Ok(text_result(serde_json::to_string_pretty(&list).unwrap_or_default()))
    }

    #[tool(
        description = "Request to USE a credential. Returns a scoped action/handle or a denial — never the plaintext secret. On an allowed mintable item, mints a fresh short-TTL scoped token held server-side. Enforces origin-binding (anti confused-deputy), propose-not-commit, and the never-unattended floor."
    )]
    async fn use_credential(
        &self,
        Parameters(args): Parameters<UseCredentialArgs>,
    ) -> Result<CallToolResult, McpError> {
        let verb = match ActionVerb::parse(&args.verb) {
            Some(v) => v,
            None => {
                return Ok(text_result(format!(
                    "unknown verb '{}' — see the tool description for valid verbs.",
                    args.verb
                )))
            }
        };
        let mode = if args.unattended {
            Mode::Unattended
        } else {
            Mode::Attended
        };

        // Phase 1: reach a decision under the lock (broker is sync).
        enum Next {
            Respond(serde_json::Value),
            Mint {
                item_id: String,
                base: Option<String>,
                scope: MintScope,
            },
        }

        let next = {
            let mut state = self.state.lock().await;
            let item = match state.items.iter().find(|i| i.id == args.item_id).cloned() {
                Some(i) => i,
                None => {
                    return Ok(text_result(format!("no such item '{}'", args.item_id)))
                }
            };
            let action = Action::new(verb, &args.origin);
            match state
                .broker
                .request_use(&item, &action, mode, args.want_raw_secret, SystemTime::now())
            {
                Ok(Grant::Capability(cap)) => match cap.primitive {
                    Primitive::Minted => {
                        let base = state.secrets.get(&item.id).cloned();
                        Next::Mint {
                            item_id: item.id.clone(),
                            base,
                            scope: scope_for(verb),
                        }
                    }
                    Primitive::Secretless => Next::Respond(json!({
                        "decision": "allow",
                        "primitive": "secretless",
                        "note": "the broker performs the action; the secret never leaves the server and is never returned to the model"
                    })),
                    Primitive::RawSecret => Next::Respond(json!({
                        "decision": "allow",
                        "primitive": "raw",
                        "note": "raw path (disabled by default)"
                    })),
                },
                Ok(Grant::NeedsHumanApproval(reason)) => Next::Respond(json!({
                    "decision": "step_up", "reason": reason,
                    "note": "requires a human to approve before it can proceed"
                })),
                Ok(Grant::Proposed(v)) => Next::Respond(json!({
                    "decision": "propose_not_commit", "proposed_verb": v.as_str(),
                    "note": "irreversible action offered as a reviewable artifact instead of executing"
                })),
                Err(Denied::OriginMismatch) => Next::Respond(json!({
                    "decision": "deny",
                    "reason": "origin mismatch — confused-deputy blocked (credential not bound to this origin)"
                })),
                Err(Denied::Policy(reason)) => Next::Respond(json!({
                    "decision": "deny", "reason": reason
                })),
            }
        };

        // Phase 2: mint outside the lock (network I/O), then store server-side.
        let out = match next {
            Next::Respond(v) => v,
            Next::Mint { item_id, base, scope } => match base {
                None => json!({
                    "decision": "allow", "primitive": "minted",
                    "note": "decision allows minting, but no base secret is loaded (running without a vault). Load a vault (PROCTOR_VAULT/PROCTOR_MASTER) to mint."
                }),
                Some(secret) => match self.minter.mint(&item_id, &secret, &scope).await {
                    Ok(token) => {
                        let mut state = self.state.lock().await;
                        let token_ref = format!("mint_{}", state.minted.len() + 1);
                        let resp = json!({
                            "decision": "allow",
                            "primitive": "minted",
                            "provider": token.provider,
                            "token_ref": token_ref,
                            "masked": token.masked(),
                            "scope": token.scope_desc,
                            "provider_expires_at": token.provider_expires_at,
                            "note": "a fresh, scoped, short-TTL token was minted and is held server-side; it is NOT returned to the model. Blast radius is bounded by scope + short TTL."
                        });
                        state.minted.insert(token_ref, token);
                        resp
                    }
                    Err(e) => json!({ "decision": "error", "reason": format!("mint failed: {e}") }),
                },
            },
        };

        Ok(text_result(serde_json::to_string_pretty(&out).unwrap_or_default()))
    }

    #[tool(
        description = "Return the tamper-evident (hash-chained) audit log of every broker decision this session, with its verification status."
    )]
    async fn audit_log(&self) -> Result<CallToolResult, McpError> {
        let state = self.state.lock().await;
        let entries: Vec<_> = state
            .broker
            .audit
            .entries()
            .iter()
            .map(|e| {
                json!({
                    "seq": e.seq, "item": e.item_id, "origin": e.origin,
                    "verb": e.verb, "decision": e.decision,
                })
            })
            .collect();
        let out = json!({ "verified": state.broker.audit.verify(), "entries": entries });
        Ok(text_result(serde_json::to_string_pretty(&out).unwrap_or_default()))
    }
}

fn text_result(s: String) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(s)])
}

#[tool_handler]
impl ServerHandler for ProctorServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_instructions(
                "Proctor credential broker. Tools: list_credentials, use_credential, audit_log. \
                 The broker returns scoped actions/handles, never plaintext secrets; it enforces \
                 origin-binding, propose-not-commit, and a never-unattended floor. Mintable items \
                 yield fresh short-TTL scoped tokens held server-side."
                    .to_string(),
            )
    }
}

/// Build the server from the environment: a real vault if configured, else demo.
fn build_server() -> ProctorServer {
    let minter: Arc<dyn Minter> = match (
        std::env::var("PROCTOR_GH_APP_ID"),
        std::env::var("PROCTOR_GH_INSTALLATION_ID"),
    ) {
        (Ok(app), Ok(inst)) if !app.is_empty() && !inst.is_empty() => {
            eprintln!("proctor-mcp: using GitHub App minter (app {app})");
            Arc::new(GitHubAppMinter::new(app, inst, RealSigner, ReqwestHttp::new()))
        }
        _ => Arc::new(MockMinter),
    };

    let vault = std::env::var("PROCTOR_VAULT").map(PathBuf::from);
    let master = std::env::var("PROCTOR_MASTER");

    if let (Ok(path), Ok(master)) = (&vault, &master) {
        if path.exists() {
            match proctor_vault::load_from_file(path, master.as_bytes()) {
                Ok(items) => {
                    let mut refs = Vec::new();
                    let mut secrets = HashMap::new();
                    for it in &items {
                        refs.push(ItemRef {
                            id: it.id.clone(),
                            label: it.label.clone(),
                            bound_origins: it.bound_origins.clone(),
                            mintable: it.mintable,
                        });
                        secrets.insert(it.id.clone(), it.secret.clone());
                    }
                    let approved = approved_origins(&refs);
                    eprintln!("proctor-mcp: loaded vault {} ({} items)", path.display(), refs.len());
                    return ProctorServer::with(refs, secrets, minter, &approved);
                }
                Err(e) => eprintln!("proctor-mcp: failed to open vault ({e}); falling back to demo items"),
            }
        } else {
            eprintln!("proctor-mcp: vault {} not found; using demo items", path.display());
        }
    } else {
        eprintln!("proctor-mcp: PROCTOR_VAULT/PROCTOR_MASTER not set; using demo items");
    }

    // Demo fallback: metadata only, no secrets (minting reports "no base secret").
    let items = vec![
        ItemRef { id: "itm_github".into(), label: "GitHub".into(), bound_origins: vec!["github.com".into()], mintable: true },
        ItemRef { id: "itm_bank".into(), label: "Bank".into(), bound_origins: vec!["bank.com".into()], mintable: false },
    ];
    let approved = approved_origins(&items);
    ProctorServer::with(items, HashMap::new(), minter, &approved)
}

/// The auto-approve origin list: env override, else the union of item origins.
fn approved_origins(items: &[ItemRef]) -> Vec<String> {
    if let Ok(csv) = std::env::var("PROCTOR_APPROVED_ORIGINS") {
        return csv.split(',').map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()).collect();
    }
    let mut o: Vec<String> = items.iter().flat_map(|i| i.bound_origins.clone()).collect();
    o.sort();
    o.dedup();
    o
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    eprintln!("proctor-mcp: credential broker starting on stdio");
    let service = build_server().serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_with_secret() -> ProctorServer {
        let items = vec![ItemRef {
            id: "itm_github".into(),
            label: "GitHub".into(),
            bound_origins: vec!["github.com".into()],
            mintable: true,
        }];
        let mut secrets = HashMap::new();
        secrets.insert("itm_github".to_string(), "SUPER_SECRET_BASE_PEM".to_string());
        ProctorServer::with(items, secrets, Arc::new(MockMinter), &["github.com".to_string()])
    }

    fn body(res: &CallToolResult) -> String {
        serde_json::to_string(res).unwrap()
    }

    #[tokio::test]
    async fn minted_response_never_leaks_the_secret() {
        let server = server_with_secret();
        let args = UseCredentialArgs {
            item_id: "itm_github".into(),
            origin: "github.com".into(),
            verb: "Read".into(),
            unattended: true,
            want_raw_secret: false,
        };
        let res = server.use_credential(Parameters(args)).await.unwrap();
        let s = body(&res);
        assert!(s.contains("minted"), "expected a minted decision: {s}");
        assert!(s.contains("masked"));
        // The invariant: neither the base secret nor the minted token value appears.
        assert!(!s.contains("SUPER_SECRET_BASE_PEM"), "base secret leaked!");
        assert!(!s.contains("ephemeral_token"), "minted token value leaked!");
    }

    #[tokio::test]
    async fn handler_blocks_confused_deputy() {
        let server = server_with_secret();
        let args = UseCredentialArgs {
            item_id: "itm_github".into(),
            origin: "evil.example.com".into(),
            verb: "Read".into(),
            unattended: true,
            want_raw_secret: false,
        };
        let res = server.use_credential(Parameters(args)).await.unwrap();
        assert!(body(&res).contains("origin mismatch"));
    }

    #[tokio::test]
    async fn ship_to_prod_is_proposed_not_committed() {
        let server = server_with_secret();
        let args = UseCredentialArgs {
            item_id: "itm_github".into(),
            origin: "github.com".into(),
            verb: "ShipToProduction".into(),
            unattended: true,
            want_raw_secret: false,
        };
        let res = server.use_credential(Parameters(args)).await.unwrap();
        let s = body(&res);
        assert!(s.contains("propose_not_commit"));
        assert!(s.contains("OpenPullRequest"));
    }
}
