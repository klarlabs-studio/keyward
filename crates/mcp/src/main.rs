//! proctor-mcp — the Proctor credential broker exposed as an MCP server over
//! stdio, so an agent (e.g. Claude Code) can *use* credentials through the
//! broker's security model without ever receiving plaintext.
//!
//! Tools:
//!   - `list_credentials`  — secret-free item metadata
//!   - `use_credential`    — request a scoped action/handle (never plaintext)
//!   - `audit_log`         — the tamper-evident decision trail
//!
//! Add to Claude Code's MCP config (stdio):
//!   { "command": "proctor-mcp" }   (after `cargo install --path crates/mcp`)
//!
//! NOTE: prototype. Items are seeded in-memory; in production they come from an
//! opened `proctor-vault`. Minting/secretless execution are represented as
//! decisions here, not yet wired to real providers.

use std::sync::Arc;
use std::time::SystemTime;

use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
    ErrorData as McpError, ServerHandler, ServiceExt,
};
use tokio::sync::Mutex;

use proctor_broker::{Action, ActionVerb, Broker, Denied, Grant, ItemRef, Mode, Policy, Primitive};

struct AppState {
    items: Vec<ItemRef>,
    broker: Broker,
}

#[derive(Clone)]
struct ProctorServer {
    state: Arc<Mutex<AppState>>,
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

#[tool_router]
impl ProctorServer {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(AppState {
                items: seed_items(),
                broker: Broker::new(Policy::with_approved_origins(&["github.com", "bank.com"])),
            })),
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
                serde_json::json!({
                    "id": i.id,
                    "label": i.label,
                    "bound_origins": i.bound_origins,
                    "mintable": i.mintable,
                })
            })
            .collect();
        Ok(CallToolResult::success(vec![ContentBlock::text(
            serde_json::to_string_pretty(&list).unwrap_or_default(),
        )]))
    }

    #[tool(
        description = "Request to USE a credential. Returns a scoped action/handle or a denial — never the plaintext secret. Enforces origin-binding (anti confused-deputy), propose-not-commit, and the never-unattended floor."
    )]
    async fn use_credential(
        &self,
        Parameters(args): Parameters<UseCredentialArgs>,
    ) -> Result<CallToolResult, McpError> {
        let verb = match ActionVerb::parse(&args.verb) {
            Some(v) => v,
            None => {
                return Ok(CallToolResult::success(vec![ContentBlock::text(format!(
                    "unknown verb '{}' — see the tool description for valid verbs.",
                    args.verb
                ))]))
            }
        };
        let mode = if args.unattended {
            Mode::Unattended
        } else {
            Mode::Attended
        };

        let mut state = self.state.lock().await;
        let item = match state.items.iter().find(|i| i.id == args.item_id).cloned() {
            Some(i) => i,
            None => {
                return Ok(CallToolResult::success(vec![ContentBlock::text(format!(
                    "no such item '{}'",
                    args.item_id
                ))]))
            }
        };

        let action = Action::new(verb, &args.origin);
        let outcome = match state
            .broker
            .request_use(&item, &action, mode, args.want_raw_secret, SystemTime::now())
        {
            Ok(Grant::Capability(c)) => serde_json::json!({
                "decision": "allow",
                "primitive": format!("{:?}", c.primitive),
                "capability_id": c.id.to_string(),
                "origin": c.origin.0,
                "verb": c.verb.as_str(),
                "uses_remaining": c.uses_remaining,
                "note": match c.primitive {
                    Primitive::Minted => "agent receives a freshly minted, scoped, short-TTL token",
                    Primitive::Secretless => "broker performs the action; the agent never receives the secret",
                    Primitive::RawSecret => "raw secret",
                }
            }),
            Ok(Grant::NeedsHumanApproval(reason)) => serde_json::json!({
                "decision": "step_up",
                "reason": reason,
                "note": "requires a human to approve before it can proceed"
            }),
            Ok(Grant::Proposed(v)) => serde_json::json!({
                "decision": "propose_not_commit",
                "proposed_verb": v.as_str(),
                "note": "irreversible action offered as a reviewable artifact instead of executing"
            }),
            Err(Denied::OriginMismatch) => serde_json::json!({
                "decision": "deny",
                "reason": "origin mismatch — confused-deputy blocked (credential not bound to this origin)"
            }),
            Err(Denied::Policy(reason)) => serde_json::json!({
                "decision": "deny",
                "reason": reason
            }),
        };

        Ok(CallToolResult::success(vec![ContentBlock::text(
            serde_json::to_string_pretty(&outcome).unwrap_or_default(),
        )]))
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
                serde_json::json!({
                    "seq": e.seq,
                    "item": e.item_id,
                    "origin": e.origin,
                    "verb": e.verb,
                    "decision": e.decision,
                })
            })
            .collect();
        let out = serde_json::json!({
            "verified": state.broker.audit.verify(),
            "entries": entries,
        });
        Ok(CallToolResult::success(vec![ContentBlock::text(
            serde_json::to_string_pretty(&out).unwrap_or_default(),
        )]))
    }
}

#[tool_handler]
impl ServerHandler for ProctorServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_instructions(
                "Proctor credential broker. Tools: list_credentials, use_credential, audit_log. \
                 The broker returns scoped actions/handles, never plaintext secrets; it enforces \
                 origin-binding, propose-not-commit, and a never-unattended floor."
                    .to_string(),
            )
    }
}

fn seed_items() -> Vec<ItemRef> {
    // In production these come from an opened proctor-vault; the broker only
    // ever receives secret-free metadata like this.
    vec![
        ItemRef {
            id: "itm_github".into(),
            label: "GitHub".into(),
            bound_origins: vec!["github.com".into()],
            mintable: true,
        },
        ItemRef {
            id: "itm_bank".into(),
            label: "Bank".into(),
            bound_origins: vec!["bank.com".into()],
            mintable: false,
        },
    ]
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Log to stderr only — stdout is the MCP protocol channel.
    eprintln!("proctor-mcp: credential broker starting on stdio");
    let service = ProctorServer::new().serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
