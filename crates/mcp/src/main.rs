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
    elicit_safe,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars, tool, tool_handler, tool_router,
    service::{Peer, RequestContext, RoleServer},
    transport::stdio,
    ErrorData as McpError, ServerHandler, ServiceExt,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use proctor_broker::{Action, ActionVerb, Broker, Denied, Grant, ItemRef, Mode, Policy, Primitive};
use proctor_mint::aws::{AwsWebIdentityMinter, ReqwestRawHttp};
use proctor_mint::exchange::{ReqwestFormHttp, TokenExchangeMinter};
use proctor_mint::exec::{ExecAction, ExecKind, Executor, GitHubExecutor, MockExecutor, ReqwestClient};
use proctor_mint::github::{GitHubAppMinter, RealSigner, ReqwestHttp};
use proctor_mint::run::{run_isolated, Isolation};
use proctor_mint::{MintScope, MintedToken, Minter, MockMinter};
use proctor_profiles::{Registry, RiskClass};

struct AppState {
    items: Vec<ItemRef>,
    /// item_id → durable base secret (zeroized on drop). Server-side only; never model-facing.
    secrets: HashMap<String, Zeroizing<String>>,
    /// item_id → provider profile id (links an item to how it injects + binds).
    providers: HashMap<String, String>,
    broker: Broker,
    /// token_ref → minted token, held server-side for the executor.
    minted: HashMap<String, MintedToken>,
}

#[derive(Clone)]
struct ProctorServer {
    state: Arc<Mutex<AppState>>,
    minter: Arc<dyn Minter>,
    /// Per-mint-kind minters (e.g. "aws-sts", "token-exchange"); routed by the
    /// item's provider profile. Falls back to `minter` (the default).
    minters: HashMap<String, Arc<dyn Minter>>,
    executor: Arc<dyn Executor>,
    profiles: Arc<Registry>,
    isolation: Isolation,
    /// Untrusted posture: refuse run_command unless OS isolation is configured.
    require_isolation: bool,
    // Used by the #[tool_router]/#[tool_handler] macro machinery.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

/// Map a verb to an executable operation, if the broker can perform it
/// secretlessly on the agent's behalf. `None` → mint-and-hold / note only.
fn exec_kind_for(v: ActionVerb) -> Option<ExecKind> {
    match v {
        ActionVerb::Read | ActionVerb::FetchData => Some(ExecKind::Read),
        ActionVerb::OpenPullRequest => Some(ExecKind::OpenPullRequest),
        _ => None,
    }
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
    /// Operation parameters passed to the performed action, e.g. for
    /// OpenPullRequest: { "owner", "repo", "head", "base", "title" }.
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct RunCommandArgs {
    /// The vault item whose credential to inject (must have a provider profile).
    item_id: String,
    /// The program to run (must be authorized by the item's provider profile).
    program: String,
    /// Arguments to the program (the credential is never placed here).
    #[serde(default)]
    args: Vec<String>,
    /// True if running unattended (no human to approve a mutating command).
    #[serde(default)]
    unattended: bool,
}

/// Interactive approval collected from the user for a step-up (high-risk) action.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[schemars(description = "Approve this step-up credential action?")]
struct Approval {
    #[schemars(description = "Set true to approve, false to reject")]
    approved: bool,
}
elicit_safe!(Approval);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApprovalOutcome {
    Approved,
    Rejected,
    /// The client can't collect approval (no elicitation support / errored).
    Unavailable,
}

/// Asks a human to approve a step-up action.
#[async_trait::async_trait]
trait Approver: Send + Sync {
    async fn request(&self, reason: &str) -> ApprovalOutcome;
}

/// Real approver: prompts the MCP client via elicitation.
struct ElicitApprover {
    peer: Peer<RoleServer>,
}

#[async_trait::async_trait]
impl Approver for ElicitApprover {
    async fn request(&self, reason: &str) -> ApprovalOutcome {
        match self
            .peer
            .elicit::<Approval>(format!("Proctor step-up approval required: {reason}"))
            .await
        {
            Ok(Some(a)) if a.approved => ApprovalOutcome::Approved,
            Ok(Some(_)) => ApprovalOutcome::Rejected,
            Ok(None) => ApprovalOutcome::Rejected,
            Err(_) => ApprovalOutcome::Unavailable,
        }
    }
}

/// Tag a result as human-approved (for the step-up path).
fn with_approved(mut v: serde_json::Value, approved: bool) -> serde_json::Value {
    if approved {
        if let Some(o) = v.as_object_mut() {
            o.insert("approved_via".into(), json!("human elicitation"));
        }
    }
    v
}

/// Which scope a minted token should carry for a given verb. Writes get a
/// narrower-but-write scope; everything else is read-only.
fn scope_for(verb: ActionVerb) -> MintScope {
    match verb {
        ActionVerb::OpenPullRequest => {
            let mut permissions = std::collections::BTreeMap::new();
            permissions.insert("contents".to_string(), "read".to_string());
            permissions.insert("pull_requests".to_string(), "write".to_string());
            MintScope { permissions, resources: Vec::new() }
        }
        _ => MintScope::read_only(),
    }
}

#[tool_router]
impl ProctorServer {
    #[allow(clippy::too_many_arguments)]
    fn with(
        items: Vec<ItemRef>,
        secrets: HashMap<String, String>,
        providers: HashMap<String, String>,
        minter: Arc<dyn Minter>,
        minters: HashMap<String, Arc<dyn Minter>>,
        executor: Arc<dyn Executor>,
        profiles: Arc<Registry>,
        isolation: Isolation,
        approved_origins: &[String],
        audit_path: Option<PathBuf>,
    ) -> Self {
        let approved: Vec<&str> = approved_origins.iter().map(|s| s.as_str()).collect();
        let policy = Policy::with_approved_origins(&approved);
        let broker = match audit_path {
            Some(p) => Broker::with_audit_file(policy, p),
            None => Broker::new(policy),
        };
        ProctorServer {
            state: Arc::new(Mutex::new(AppState {
                items,
                // Wrap secrets so they are wiped from memory when dropped.
                secrets: secrets.into_iter().map(|(k, v)| (k, Zeroizing::new(v))).collect(),
                providers,
                broker,
                minted: HashMap::new(),
            })),
            minter,
            minters,
            executor,
            profiles,
            isolation,
            require_isolation: false,
            tool_router: Self::tool_router(),
        }
    }

    /// Untrusted posture: require OS isolation for run_command (builder).
    fn with_require_isolation(mut self, v: bool) -> Self {
        self.require_isolation = v;
        self
    }

    /// The minter for an item's provider (by its profile's `mint` kind), or the
    /// default. Returns None only if there is genuinely no minter to use.
    fn minter_for(&self, provider_id: &str) -> Arc<dyn Minter> {
        if let Some(kind) = self.profiles.get(provider_id).and_then(|p| p.mint.clone()) {
            if let Some(m) = self.minters.get(&kind) {
                return m.clone();
            }
        }
        self.minter.clone()
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
        description = "Request to USE a credential. Returns a scoped action/handle or a denial — never the plaintext secret. On an allowed read/write the broker performs the action itself (secretless) using the vault token or a minted scoped token; `params` carries operation fields (e.g. OpenPullRequest: owner, repo, head, base, title). Enforces origin-binding (anti confused-deputy), propose-not-commit, and the never-unattended floor."
    )]
    async fn use_credential(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(args): Parameters<UseCredentialArgs>,
    ) -> Result<CallToolResult, McpError> {
        let approver = ElicitApprover { peer: context.peer.clone() };
        let out = self.handle_use(args, &approver).await;
        Ok(text_result(serde_json::to_string_pretty(&out).unwrap_or_default()))
    }

    /// Core decision + execution logic, independent of the MCP transport so it is
    /// unit-testable. On a step-up decision it asks `approver` (real elicitation
    /// in production, a mock in tests).
    async fn handle_use(&self, args: UseCredentialArgs, approver: &dyn Approver) -> serde_json::Value {
        let verb = match ActionVerb::parse(&args.verb) {
            Some(v) => v,
            None => return json!({ "decision": "error", "reason": format!("unknown verb '{}'", args.verb) }),
        };
        let mode = if args.unattended { Mode::Unattended } else { Mode::Attended };

        enum Plan {
            Value(serde_json::Value),
            Exec { mintable: bool, item_id: String, base: Option<Zeroizing<String>>, verb: ActionVerb, origin: String, params: serde_json::Value },
            StepUp { reason: String, mintable: bool, item_id: String, base: Option<Zeroizing<String>>, verb: ActionVerb, origin: String, params: serde_json::Value },
        }

        // Decide under the lock (broker is sync); execute/elicit after releasing it.
        let plan = {
            let mut state = self.state.lock().await;
            let item = match state.items.iter().find(|i| i.id == args.item_id).cloned() {
                Some(i) => i,
                None => return json!({ "decision": "error", "reason": format!("no such item '{}'", args.item_id) }),
            };
            let action = Action::new(verb, &args.origin);
            match state.broker.request_use(&item, &action, mode, args.want_raw_secret, SystemTime::now()) {
                Ok(Grant::Capability(cap)) => {
                    let base = state.secrets.get(&item.id).cloned();
                    match cap.primitive {
                        Primitive::Minted => Plan::Exec { mintable: true, item_id: item.id.clone(), base, verb, origin: action.target.0.clone(), params: args.params.clone() },
                        Primitive::Secretless => Plan::Exec { mintable: false, item_id: item.id.clone(), base, verb, origin: action.target.0.clone(), params: args.params.clone() },
                        Primitive::RawSecret => Plan::Value(json!({ "decision": "allow", "primitive": "raw", "note": "raw path (disabled by default)" })),
                    }
                }
                Ok(Grant::NeedsHumanApproval(reason)) => {
                    if exec_kind_for(verb).is_some() {
                        Plan::StepUp { reason, mintable: item.mintable, item_id: item.id.clone(), base: state.secrets.get(&item.id).cloned(), verb, origin: action.target.0.clone(), params: args.params.clone() }
                    } else {
                        Plan::Value(json!({ "decision": "step_up", "reason": reason, "note": "requires a human to approve; no automated execution is wired for this verb." }))
                    }
                }
                Ok(Grant::Proposed(v)) => Plan::Value(json!({ "decision": "propose_not_commit", "proposed_verb": v.as_str(), "note": "irreversible action offered as a reviewable artifact instead of executing" })),
                Err(Denied::OriginMismatch) => Plan::Value(json!({ "decision": "deny", "reason": "origin mismatch — confused-deputy blocked (credential not bound to this origin)" })),
                Err(Denied::Policy(reason)) => Plan::Value(json!({ "decision": "deny", "reason": reason })),
            }
        };

        match plan {
            Plan::Value(v) => v,
            Plan::Exec { mintable, item_id, base, verb, origin, params } => {
                self.execute(mintable, item_id, base, verb, origin, params, false).await
            }
            Plan::StepUp { reason, mintable, item_id, base, verb, origin, params } => {
                match approver.request(&reason).await {
                    ApprovalOutcome::Approved => {
                        {
                            let mut s = self.state.lock().await;
                            s.broker.audit.append(&item_id, &origin, verb.as_str(), "STEPUP:approved");
                        }
                        self.execute(mintable, item_id, base, verb, origin, params, true).await
                    }
                    ApprovalOutcome::Rejected => json!({ "decision": "deny", "reason": format!("human rejected step-up: {reason}") }),
                    ApprovalOutcome::Unavailable => json!({ "decision": "step_up", "reason": reason, "note": "human approval required; interactive elicitation is unavailable on this client." }),
                }
            }
        }
    }

    /// Perform an allowed action: mint (mintable) or read the stored token
    /// (vault), then execute via the executor. The credential is never returned.
    async fn execute(
        &self,
        mintable: bool,
        item_id: String,
        base: Option<Zeroizing<String>>,
        verb: ActionVerb,
        origin: String,
        params: serde_json::Value,
        approved: bool,
    ) -> serde_json::Value {
        let secret = match base {
            Some(s) => s,
            None => return json!({
                "decision": "allow",
                "primitive": if mintable { "minted" } else { "secretless" },
                "note": "decision allows the action, but no credential is loaded (running without a vault). Load a vault via PROCTOR_VAULT/PROCTOR_MASTER."
            }),
        };
        let kind = exec_kind_for(verb);

        if mintable {
            let token = match self.minter.mint(&item_id, &secret, &scope_for(verb)).await {
                Ok(t) => t,
                Err(e) => return json!({ "decision": "error", "reason": format!("mint failed: {e}") }),
            };
            match kind {
                Some(k) => {
                    let ea = ExecAction::with_params(k, origin, params);
                    match self.executor.perform(token.expose(), &ea).await {
                        Ok(r) => with_approved(json!({
                            "decision": "allow", "primitive": "secretless_exec", "source": "minted",
                            "provider": self.executor.provider(), "performed": true,
                            "result_summary": r.summary, "result": r.data,
                            "note": "the broker minted a scoped short-TTL token and performed the action itself; neither the base secret nor the minted token was returned to the model."
                        }), approved),
                        Err(e) => json!({ "decision": "error", "reason": format!("execution failed: {e}") }),
                    }
                }
                None => {
                    let mut state = self.state.lock().await;
                    let token_ref = format!("mint_{}", state.minted.len() + 1);
                    let resp = with_approved(json!({
                        "decision": "allow", "primitive": "minted", "provider": token.provider,
                        "token_ref": token_ref, "masked": token.masked(), "scope": token.scope_desc,
                        "provider_expires_at": token.provider_expires_at,
                        "note": "a fresh, scoped, short-TTL token was minted and is held server-side; it is NOT returned to the model."
                    }), approved);
                    state.minted.insert(token_ref, token);
                    resp
                }
            }
        } else {
            match kind {
                Some(k) => {
                    let ea = ExecAction::with_params(k, origin, params);
                    match self.executor.perform(&secret, &ea).await {
                        Ok(r) => with_approved(json!({
                            "decision": "allow", "primitive": "secretless_exec", "source": "vault",
                            "provider": self.executor.provider(), "performed": true,
                            "result_summary": r.summary, "result": r.data,
                            "note": "the broker read the stored credential from the vault and performed the action itself; the credential was never returned to the model."
                        }), approved),
                        Err(e) => json!({ "decision": "error", "reason": format!("execution failed: {e}") }),
                    }
                }
                None => json!({
                    "decision": "allow", "primitive": "secretless",
                    "note": format!("the broker would perform '{}' using the stored credential; no execution is wired for this verb yet.", verb.as_str())
                }),
            }
        }
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

    #[tool(
        description = "List the short-lived tokens minted and held server-side this session (reference + provider + masked view). Never returns token values."
    )]
    async fn list_minted(&self) -> Result<CallToolResult, McpError> {
        let state = self.state.lock().await;
        let list: Vec<_> = state
            .minted
            .iter()
            .map(|(r, t)| json!({ "token_ref": r, "provider": t.provider, "masked": t.masked(), "scope": t.scope_desc }))
            .collect();
        Ok(text_result(serde_json::to_string_pretty(&json!({ "count": list.len(), "minted": list })).unwrap_or_default()))
    }

    #[tool(
        description = "Kill switch: revoke all server-held minted tokens immediately. Audited."
    )]
    async fn revoke_all(&self) -> Result<CallToolResult, McpError> {
        let mut state = self.state.lock().await;
        let n = state.minted.len();
        state.minted.clear();
        state.broker.audit.append("*", "*", "RevokeAll", &format!("REVOKE-ALL:{n}-tokens"));
        Ok(text_result(serde_json::to_string_pretty(&json!({ "revoked": n })).unwrap_or_default()))
    }

    #[tool(
        description = "Run a CLI command with the item's credential injected into the subprocess environment (never argv), and return only the (redacted) output. The program must be authorized by the item's provider profile (anti confused-deputy); read commands run, mutating/unknown commands are gated (step-up when attended, denied unattended)."
    )]
    async fn run_command(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(args): Parameters<RunCommandArgs>,
    ) -> Result<CallToolResult, McpError> {
        let approver = ElicitApprover { peer: context.peer.clone() };
        let out = self.handle_run(args, &approver).await;
        Ok(text_result(serde_json::to_string_pretty(&out).unwrap_or_default()))
    }

    async fn handle_run(&self, args: RunCommandArgs, approver: &dyn Approver) -> serde_json::Value {
        let mode = if args.unattended { Mode::Unattended } else { Mode::Attended };

        // (0) Trust gate — in untrusted mode, refuse to inject a credential into a
        // subprocess without OS isolation (env injection is not a boundary).
        if self.require_isolation && matches!(self.isolation, Isolation::None) {
            return json!({
                "decision": "deny",
                "reason": "run_command requires OS isolation in untrusted mode; set PROCTOR_ISOLATION (e.g. docker:<image> or bwrap), or PROCTOR_TRUST=trusted for a trusted host."
            });
        }

        // Gather secret + provider + mintable under the lock.
        let (secret, provider_id, mintable) = {
            let state = self.state.lock().await;
            let mintable = match state.items.iter().find(|i| i.id == args.item_id) {
                Some(i) => i.mintable,
                None => return json!({ "decision": "error", "reason": format!("no such item '{}'", args.item_id) }),
            };
            let provider = match state.providers.get(&args.item_id) {
                Some(p) => p.clone(),
                None => return json!({ "decision": "error", "reason": "item has no provider profile; set one to run commands" }),
            };
            match state.secrets.get(&args.item_id) {
                Some(s) => (s.clone(), provider, mintable),
                None => return json!({ "decision": "allow", "note": "no credential loaded (running without a vault)" }),
            }
        };

        let profile = match self.profiles.get(&provider_id) {
            Some(p) => p,
            None => return json!({ "decision": "error", "reason": format!("unknown provider profile '{provider_id}' (add {provider_id}.toml)") }),
        };

        // (1) Command-binding — the program must be one this credential authorizes.
        if !profile.commands.is_empty() && !profile.commands.iter().any(|c| c == &args.program) {
            self.audit(&args.item_id, &provider_id, &args.program, "RUN-DENY:command-not-authorized").await;
            return json!({
                "decision": "deny",
                "reason": format!("'{}' is not authorized for credential '{}' — confused-deputy blocked", args.program, args.item_id)
            });
        }
        // Shells run arbitrary work past command-binding — blocked unless opted in.
        if proctor_profiles::is_shell_interpreter(&args.program) && !profile.allow_shell {
            self.audit(&args.item_id, &provider_id, &args.program, "RUN-DENY:shell-not-permitted").await;
            return json!({
                "decision": "deny",
                "reason": format!("'{}' is a shell interpreter and is not permitted for this credential; set allow_shell = true on the profile to override", args.program)
            });
        }

        // (2) Command-risk gate.
        let mut argv = vec![args.program.clone()];
        argv.extend(args.args.clone());
        let risk = profile.classify(&argv);
        let proceed = match risk {
            RiskClass::Read => true,
            RiskClass::Mutate | RiskClass::Unknown => match mode {
                Mode::Attended => match approver.request(&format!("run `{}` (risk: {:?})", argv.join(" "), risk)).await {
                    ApprovalOutcome::Approved => {
                        self.audit(&args.item_id, &provider_id, &args.program, "RUN-STEPUP:approved").await;
                        true
                    }
                    ApprovalOutcome::Rejected => {
                        self.audit(&args.item_id, &provider_id, &args.program, "RUN-DENY:rejected").await;
                        return json!({ "decision": "deny", "reason": "human rejected the mutating/unknown command" });
                    }
                    ApprovalOutcome::Unavailable => {
                        return json!({ "decision": "step_up", "reason": format!("`{}` is {:?}; human approval required", argv.join(" "), risk) });
                    }
                },
                Mode::Unattended => {
                    self.audit(&args.item_id, &provider_id, &args.program, "RUN-DENY:mutating-unattended").await;
                    return json!({ "decision": "deny", "reason": format!("`{}` is {:?} and cannot run unattended", argv.join(" "), risk) });
                }
            },
        };
        let _ = proceed;

        // (3) Prefer a minted short-TTL credential on the exec path — it bounds
        // how long a leaked value (via /proc, etc.) stays useful. Falls back to
        // the stored secret when the item isn't mintable or the minted token
        // doesn't fit the profile (e.g. multi-field env_map).
        let mut cred_source = "stored";
        let mut inject = secret.clone();
        if mintable {
            // Route to the minter declared by the provider profile (mint kind).
            let minter = self.minter_for(&provider_id);
            if let Ok(tok) = minter.mint(&args.item_id, &secret, &MintScope::read_only()).await {
                // Use the minted credential only if it composes for this profile —
                // single tokens fill `env_var`, JSON trios fill `env_map`.
                if profile.compose_env(tok.expose()).is_ok() {
                    inject = Zeroizing::new(tok.expose().to_string());
                    cred_source = "minted";
                }
            }
        }

        // Compose env + run (off-thread), then redact injected values from output.
        let env = match profile.compose_env(&inject) {
            Ok(e) => e,
            Err(e) => return json!({ "decision": "error", "reason": format!("credential/profile mismatch: {e}") }),
        };
        let (program, cmdargs, env_run, iso) =
            (args.program.clone(), args.args.clone(), env.clone(), self.isolation.clone());
        let run = tokio::task::spawn_blocking(move || run_isolated(&iso, &program, &cmdargs, &env_run)).await;

        let redact = |mut s: String| -> String {
            for v in env.values() {
                if !v.is_empty() {
                    s = s.replace(v, "***REDACTED***");
                }
            }
            s
        };

        match run {
            Ok(Ok(r)) => {
                self.audit(&args.item_id, &provider_id, &args.program, &format!("RUN-ALLOW:exit={:?}", r.code)).await;
                let mut out = json!({
                    "decision": "allow",
                    "ran": true,
                    "provider": provider_id,
                    "command": argv.join(" "),
                    "isolation": self.isolation.label(),
                    "egress": self.isolation.egress(),
                    "credential_source": cred_source,
                    "exit_code": r.code,
                    "stdout": redact(r.stdout),
                    "stderr": redact(r.stderr),
                    "truncated": r.truncated,
                    "note": "the credential was injected into the subprocess environment and never returned to the model; any occurrences were redacted from the output."
                });
                if proctor_profiles::is_shell_interpreter(&args.program) {
                    if let Some(o) = out.as_object_mut() {
                        o.insert("shell_warning".into(), json!(
                            "authorized program is a shell interpreter; command-binding and argv risk classification cannot inspect the actual work — prefer authorizing specific tools (aws, terraform), not shells."
                        ));
                    }
                }
                if self.state.lock().await.broker.audit.write_failed() {
                    if let Some(o) = out.as_object_mut() {
                        o.insert("audit_warning".into(), json!(
                            "persistent audit write has failed — the on-disk trail is incomplete."
                        ));
                    }
                }
                out
            }
            Ok(Err(e)) => json!({ "decision": "error", "reason": format!("could not run '{}': {e}", args.program) }),
            Err(e) => json!({ "decision": "error", "reason": format!("run task failed: {e}") }),
        }
    }

    async fn audit(&self, item: &str, origin: &str, verb: &str, decision: &str) {
        let mut state = self.state.lock().await;
        state.broker.audit.append(item, origin, verb, decision);
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
                "Proctor credential broker. Tools: list_credentials, use_credential, run_command, \
                 list_minted, revoke_all, audit_log. The broker returns results/handles, never \
                 plaintext secrets; it enforces origin-binding, propose-not-commit, a never-unattended \
                 floor, and (for run_command) command-binding + risk gating with the credential \
                 injected into the subprocess environment only."
                    .to_string(),
            )
    }
}

/// Build the server from the environment: a real vault if configured, else demo.
fn build_server() -> ProctorServer {
    let gh = match (std::env::var("PROCTOR_GH_APP_ID"), std::env::var("PROCTOR_GH_INSTALLATION_ID")) {
        (Ok(a), Ok(i)) if !a.is_empty() && !i.is_empty() => Some((a, i)),
        _ => None,
    };

    // Per-mint-kind minter map for run_command routing (by provider profile).
    let mut minters: HashMap<String, Arc<dyn Minter>> = HashMap::new();
    minters.insert("mock".into(), Arc::new(MockMinter));
    if let Some((app, inst)) = &gh {
        minters.insert(
            "github-app".into(),
            Arc::new(GitHubAppMinter::new(app.clone(), inst.clone(), RealSigner, ReqwestHttp::new())),
        );
    }
    if let Ok(ep) = std::env::var("PROCTOR_STS_ENDPOINT") {
        if !ep.is_empty() && require_https(&ep, "token-exchange") {
            eprintln!("proctor-mcp: token-exchange endpoint {ep}");
            let mut m = TokenExchangeMinter::new(ep, ReqwestFormHttp::new());
            m.audience = std::env::var("PROCTOR_STS_AUDIENCE").ok();
            m.scope = std::env::var("PROCTOR_STS_SCOPE").ok();
            minters.insert("token-exchange".into(), Arc::new(m));
        }
    }
    if let Ok(arn) = std::env::var("PROCTOR_AWS_ROLE_ARN") {
        if !arn.is_empty() {
            eprintln!("proctor-mcp: aws-sts minter enabled (role {arn})");
            minters.insert("aws-sts".into(), Arc::new(AwsWebIdentityMinter::new(arn, ReqwestRawHttp::new())));
        }
    }

    // Executor: GitHub HTTP-perform if configured, else mock.
    let executor: Arc<dyn Executor> = if gh.is_some() {
        Arc::new(GitHubExecutor::new(ReqwestClient::new()))
    } else {
        Arc::new(MockExecutor)
    };

    // Minter: RFC 8693 token-exchange (STS) > GitHub App > mock.
    let minter: Arc<dyn Minter> = if let Ok(ep) = std::env::var("PROCTOR_STS_ENDPOINT") {
        if !ep.is_empty() && require_https(&ep, "token-exchange") {
            eprintln!("proctor-mcp: using RFC 8693 token-exchange minter ({ep})");
            let mut m = TokenExchangeMinter::new(ep, ReqwestFormHttp::new());
            m.audience = std::env::var("PROCTOR_STS_AUDIENCE").ok();
            m.scope = std::env::var("PROCTOR_STS_SCOPE").ok();
            if let Ok(t) = std::env::var("PROCTOR_STS_SUBJECT_TYPE") {
                m.subject_token_type = t;
            }
            Arc::new(m)
        } else {
            Arc::new(MockMinter)
        }
    } else if let Some((app, inst)) = gh {
        eprintln!("proctor-mcp: using GitHub App minter (app {app})");
        Arc::new(GitHubAppMinter::new(app, inst, RealSigner, ReqwestHttp::new()))
    } else {
        Arc::new(MockMinter)
    };

    let audit_path = std::env::var("PROCTOR_AUDIT").ok().map(PathBuf::from);
    if let Some(p) = &audit_path {
        eprintln!("proctor-mcp: appending audit log to {}", p.display());
    }

    let profiles = Arc::new(load_profiles());
    eprintln!("proctor-mcp: {} provider profile(s) loaded", profiles.len());

    let isolation = isolation_from_env();
    let require_isolation = matches!(
        std::env::var("PROCTOR_TRUST").unwrap_or_default().as_str(),
        "untrusted" | "untrust"
    );
    if matches!(isolation, Isolation::None) {
        if require_isolation {
            eprintln!("proctor-mcp: TRUST=untrusted + isolation=none — run_command will be refused until PROCTOR_ISOLATION is set");
        } else {
            eprintln!("proctor-mcp: run_command isolation = none (trusted mode; set PROCTOR_ISOLATION + PROCTOR_TRUST=untrusted for autonomy)");
        }
    } else {
        eprintln!("proctor-mcp: run_command isolation = {}", isolation.label());
    }

    let vault = std::env::var("PROCTOR_VAULT").map(PathBuf::from);
    let master = read_master();

    if let (Ok(path), Some(master)) = (&vault, &master) {
        if path.exists() {
            match proctor_vault::load_from_file(path, master.as_bytes()) {
                Ok(items) => {
                    let mut refs = Vec::new();
                    let mut secrets = HashMap::new();
                    let mut providers = HashMap::new();
                    for it in &items {
                        refs.push(ItemRef {
                            id: it.id.clone(),
                            label: it.label.clone(),
                            bound_origins: it.bound_origins.clone(),
                            mintable: it.mintable,
                        });
                        secrets.insert(it.id.clone(), it.secret.clone());
                        if let Some(p) = &it.provider {
                            providers.insert(it.id.clone(), p.clone());
                        }
                    }
                    let approved = approved_origins(&refs);
                    eprintln!("proctor-mcp: loaded vault {} ({} items)", path.display(), refs.len());
                    return ProctorServer::with(refs, secrets, providers, minter, minters, executor, profiles, isolation, &approved, audit_path)
                        .with_require_isolation(require_isolation);
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
    ProctorServer::with(items, HashMap::new(), HashMap::new(), minter, minters, executor, profiles, isolation, &approved, audit_path)
        .with_require_isolation(require_isolation)
}

/// Parse run_command isolation from $PROCTOR_ISOLATION:
///   none (default) | bwrap | docker:<image> | podman:<image>
///
/// Network egress: `$PROCTOR_ISOLATION_NETWORK` if set, else **"none" in
/// untrusted mode** (deny egress so an injected credential can't be exfiltrated
/// over the network) and "bridge" in trusted mode.
fn isolation_from_env() -> Isolation {
    let spec = std::env::var("PROCTOR_ISOLATION").unwrap_or_default();
    let untrusted = matches!(
        std::env::var("PROCTOR_TRUST").unwrap_or_default().as_str(),
        "untrusted" | "untrust"
    );
    let net_default = if untrusted { "none" } else { "bridge" };
    let network = std::env::var("PROCTOR_ISOLATION_NETWORK").unwrap_or_else(|_| net_default.to_string());
    let deny_net = network == "none";
    match spec.as_str() {
        "" | "none" => Isolation::None,
        "bwrap" | "bubblewrap" => Isolation::Bubblewrap { deny_net },
        other => {
            for rt in ["docker", "podman"] {
                if let Some(image) = other.strip_prefix(&format!("{rt}:")) {
                    return Isolation::Container {
                        runtime: rt.to_string(),
                        image: image.to_string(),
                        network: network.clone(),
                    };
                }
            }
            eprintln!("proctor-mcp: unknown PROCTOR_ISOLATION '{other}'; using none");
            Isolation::None
        }
    }
}

/// Read the vault master secret. Prefers `$PROCTOR_MASTER_FILE` (a path) so the
/// master isn't exposed via `/proc/<pid>/environ`; falls back to `$PROCTOR_MASTER`
/// with a warning.
fn read_master() -> Option<String> {
    if let Ok(path) = std::env::var("PROCTOR_MASTER_FILE") {
        match std::fs::read_to_string(&path) {
            Ok(s) => return Some(s.trim_end_matches(['\n', '\r']).to_string()),
            Err(e) => eprintln!("proctor-mcp: cannot read PROCTOR_MASTER_FILE {path}: {e}"),
        }
    }
    match std::env::var("PROCTOR_MASTER") {
        Ok(m) if !m.is_empty() => {
            eprintln!("proctor-mcp: PROCTOR_MASTER is set via env (readable via /proc); prefer PROCTOR_MASTER_FILE");
            Some(m)
        }
        _ => None,
    }
}

/// Require an https endpoint (reject cleartext, which would leak the token).
fn require_https(url: &str, what: &str) -> bool {
    if url.starts_with("https://") {
        true
    } else {
        eprintln!("proctor-mcp: refusing non-https {what} endpoint '{url}'");
        false
    }
}

/// Load provider profiles from $PROCTOR_PROFILES (or ~/.proctor/profiles).
fn load_profiles() -> Registry {
    let dir = std::env::var("PROCTOR_PROFILES")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".proctor/profiles"))
                .unwrap_or_else(|_| PathBuf::from("profiles"))
        });
    Registry::load_dir(&dir).unwrap_or_else(|e| {
        eprintln!("proctor-mcp: profile load error ({e}); continuing with none");
        Registry::new()
    })
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

    struct MockApprover(ApprovalOutcome);
    #[async_trait::async_trait]
    impl Approver for MockApprover {
        async fn request(&self, _reason: &str) -> ApprovalOutcome {
            self.0
        }
    }
    fn no_approve() -> MockApprover {
        MockApprover(ApprovalOutcome::Rejected)
    }

    fn args(item: &str, origin: &str, verb: &str, unattended: bool) -> UseCredentialArgs {
        UseCredentialArgs {
            item_id: item.into(),
            origin: origin.into(),
            verb: verb.into(),
            unattended,
            want_raw_secret: false,
            params: serde_json::Value::Null,
        }
    }

    fn server(mintable: bool, secret: &str, approved: &[&str]) -> ProctorServer {
        let items = vec![ItemRef {
            id: "itm_github".into(),
            label: "GitHub".into(),
            bound_origins: vec!["github.com".into(), "api.github.com".into()],
            mintable,
        }];
        let mut secrets = HashMap::new();
        secrets.insert("itm_github".to_string(), secret.to_string());
        let approved: Vec<String> = approved.iter().map(|s| s.to_string()).collect();
        ProctorServer::with(
            items,
            secrets,
            HashMap::new(),
            Arc::new(MockMinter),
            HashMap::new(),
            Arc::new(MockExecutor),
            Arc::new(Registry::new()),
            Isolation::None,
            &approved,
            None,
        )
    }

    fn run_server() -> ProctorServer {
        run_server_m(false)
    }

    /// A server whose item has a provider profile, for run_command tests.
    fn run_server_m(mintable: bool) -> ProctorServer {
        let items = vec![ItemRef {
            id: "itm_cli".into(),
            label: "Demo CLI cred".into(),
            bound_origins: vec![],
            mintable,
        }];
        let mut secrets = HashMap::new();
        secrets.insert("itm_cli".to_string(), "supersecret_token".to_string());
        let mut providers = HashMap::new();
        providers.insert("itm_cli".to_string(), "demo".to_string());

        // A profile that authorizes `sh`, classifies `echo`/list as read, rm as mutate.
        let mut reg = Registry::new();
        reg.insert(
            toml::from_str(
                r#"
                id = "demo"
                env_var = "DEMO_TOKEN"
                commands = ["sh"]
                allow_shell = true
                read_patterns = ['\becho\b', '\blist\b']
                mutate_patterns = ['\brm\b', '\bdelete\b']
            "#,
            )
            .unwrap(),
        )
        .unwrap();

        ProctorServer::with(
            items,
            secrets,
            providers,
            Arc::new(MockMinter),
            HashMap::new(),
            Arc::new(MockExecutor),
            Arc::new(reg),
            Isolation::None,
            &[],
            None,
        )
    }

    fn run_args(program: &str, args: &[&str], unattended: bool) -> RunCommandArgs {
        RunCommandArgs {
            item_id: "itm_cli".into(),
            program: program.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            unattended,
        }
    }

    /// Parse a CallToolResult's text content back into JSON.
    fn tool_json(res: &CallToolResult) -> serde_json::Value {
        let v = serde_json::to_value(res).unwrap();
        serde_json::from_str(v["content"][0]["text"].as_str().unwrap()).unwrap()
    }

    #[tokio::test]
    async fn minted_read_returns_result_not_secret() {
        let v = server(true, "SUPER_SECRET_BASE_PEM", &["github.com"])
            .handle_use(args("itm_github", "github.com", "Read", true), &no_approve())
            .await;
        assert_eq!(v["primitive"], "secretless_exec");
        assert_eq!(v["source"], "minted");
        assert!(v.to_string().contains("octo/demo"));
        assert!(!v.to_string().contains("SUPER_SECRET_BASE_PEM"));
        assert!(!v.to_string().contains("ephemeral_token"));
    }

    #[tokio::test]
    async fn vault_read_uses_stored_token_without_leaking_it() {
        let v = server(false, "tk_STORED_TOKEN", &["github.com"])
            .handle_use(args("itm_github", "github.com", "Read", true), &no_approve())
            .await;
        assert_eq!(v["primitive"], "secretless_exec");
        assert_eq!(v["source"], "vault");
        assert!(!v.to_string().contains("tk_STORED_TOKEN"));
    }

    #[tokio::test]
    async fn confused_deputy_is_blocked() {
        let v = server(true, "SEC", &["github.com"])
            .handle_use(args("itm_github", "evil.example.com", "Read", true), &no_approve())
            .await;
        assert_eq!(v["decision"], "deny");
        assert!(v["reason"].as_str().unwrap().contains("origin mismatch"));
    }

    #[tokio::test]
    async fn ship_to_prod_is_proposed_not_committed() {
        let v = server(false, "tk_x", &["github.com"])
            .handle_use(args("itm_github", "github.com", "ShipToProduction", true), &no_approve())
            .await;
        assert_eq!(v["decision"], "propose_not_commit");
        assert_eq!(v["proposed_verb"], "OpenPullRequest");
    }

    #[tokio::test]
    async fn open_pr_executes_as_reviewable_artifact_with_params() {
        let mut a = args("itm_github", "github.com", "OpenPullRequest", true);
        a.params = json!({ "repo": "octo/infra", "title": "Automated fix" });
        let v = server(false, "tk_x", &["github.com"]).handle_use(a, &no_approve()).await;
        assert_eq!(v["primitive"], "secretless_exec");
        let s = v.to_string();
        assert!(s.contains("pull_request"));
        assert!(s.contains("not merged"));
        assert!(s.contains("Automated fix")); // params flowed through
    }

    #[tokio::test]
    async fn non_executing_verb_mints_and_holds() {
        let v = server(true, "SEC", &["github.com"])
            .handle_use(args("itm_github", "github.com", "MintReadToken", true), &no_approve())
            .await;
        assert_eq!(v["primitive"], "minted");
        assert!(v["token_ref"].is_string());
        assert!(!v.to_string().contains("ephemeral_token"));
    }

    // --- step-up / elicitation ---

    #[tokio::test]
    async fn step_up_approved_executes() {
        // Read on a bound-but-not-pre-approved origin, attended → step-up.
        let v = server(false, "tk_STORED", &["github.com"])
            .handle_use(
                args("itm_github", "api.github.com", "Read", false),
                &MockApprover(ApprovalOutcome::Approved),
            )
            .await;
        assert_eq!(v["primitive"], "secretless_exec");
        assert_eq!(v["approved_via"], "human elicitation");
        assert!(!v.to_string().contains("tk_STORED"));
    }

    #[tokio::test]
    async fn step_up_rejected_denies() {
        let v = server(false, "tk_STORED", &["github.com"])
            .handle_use(
                args("itm_github", "api.github.com", "Read", false),
                &MockApprover(ApprovalOutcome::Rejected),
            )
            .await;
        assert_eq!(v["decision"], "deny");
        assert!(v["reason"].as_str().unwrap().contains("rejected"));
    }

    #[tokio::test]
    async fn step_up_unavailable_falls_back_to_note() {
        let v = server(false, "tk_STORED", &["github.com"])
            .handle_use(
                args("itm_github", "api.github.com", "Read", false),
                &MockApprover(ApprovalOutcome::Unavailable),
            )
            .await;
        assert_eq!(v["decision"], "step_up");
    }

    #[tokio::test]
    async fn kill_switch_revokes_held_tokens() {
        let server = server(true, "SEC", &["github.com"]);
        let _ = server
            .handle_use(args("itm_github", "github.com", "MintReadToken", true), &no_approve())
            .await;
        assert_eq!(tool_json(&server.list_minted().await.unwrap())["count"], 1);
        assert_eq!(tool_json(&server.revoke_all().await.unwrap())["revoked"], 1);
        assert_eq!(tool_json(&server.list_minted().await.unwrap())["count"], 0);
    }

    // --- run_command (generic exec-injection executor) ---

    #[tokio::test]
    async fn untrusted_mode_refuses_run_without_isolation() {
        // isolation=none + require_isolation → run_command is gated off entirely.
        let server = run_server_m(false).with_require_isolation(true);
        let v = server
            .handle_run(run_args("sh", &["-c", "echo hi"], true), &no_approve())
            .await;
        assert_eq!(v["decision"], "deny");
        assert!(v["reason"].as_str().unwrap().contains("OS isolation"));
    }

    #[tokio::test]
    async fn run_read_command_executes_and_returns_output() {
        let v = run_server()
            .handle_run(run_args("sh", &["-c", "echo hi"], true), &no_approve())
            .await;
        assert_eq!(v["decision"], "allow");
        assert_eq!(v["ran"], true);
        assert!(v["stdout"].as_str().unwrap().contains("hi"));
    }

    #[tokio::test]
    async fn run_redacts_the_injected_secret_from_output() {
        // The command echoes the injected env value; our return channel must redact it.
        let v = run_server()
            .handle_run(run_args("sh", &["-c", "echo $DEMO_TOKEN"], true), &no_approve())
            .await;
        let s = v.to_string();
        assert!(s.contains("REDACTED"), "expected redaction: {s}");
        assert!(!s.contains("supersecret_token"), "secret leaked through output!");
    }

    #[tokio::test]
    async fn run_blocks_shell_without_allow_shell() {
        // A profile that lists `sh` but does NOT set allow_shell must refuse it.
        let items = vec![ItemRef { id: "itm".into(), label: "x".into(), bound_origins: vec![], mintable: false }];
        let mut secrets = HashMap::new();
        secrets.insert("itm".to_string(), "s".to_string());
        let mut providers = HashMap::new();
        providers.insert("itm".to_string(), "p".to_string());
        let mut reg = Registry::new();
        reg.insert(toml::from_str(r#"id="p"
            env_var="T"
            commands=["sh"]"#).unwrap()).unwrap(); // allow_shell defaults false
        let server = ProctorServer::with(
            items, secrets, providers, Arc::new(MockMinter), HashMap::new(),
            Arc::new(MockExecutor), Arc::new(reg), Isolation::None, &[], None,
        );
        let v = server.handle_run(run_args_for("itm", "sh", &["-c", "echo hi"], true), &no_approve()).await;
        assert_eq!(v["decision"], "deny");
        assert!(v["reason"].as_str().unwrap().contains("shell interpreter"));
    }

    fn run_args_for(item: &str, program: &str, args: &[&str], unattended: bool) -> RunCommandArgs {
        RunCommandArgs {
            item_id: item.into(),
            program: program.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            unattended,
        }
    }

    #[tokio::test]
    async fn run_blocks_unauthorized_program() {
        // `curl` is not in the profile's commands → confused-deputy blocked.
        let v = run_server()
            .handle_run(run_args("curl", &["https://evil.example.com"], true), &no_approve())
            .await;
        assert_eq!(v["decision"], "deny");
        assert!(v["reason"].as_str().unwrap().contains("confused-deputy"));
    }

    #[tokio::test]
    async fn run_mutate_unattended_is_denied() {
        let v = run_server()
            .handle_run(run_args("sh", &["-c", "echo delete"], true), &no_approve())
            .await;
        assert_eq!(v["decision"], "deny");
    }

    // Multi-field minted credential (AWS STS trio) routed by profile.mint.
    struct FakeSts;
    #[async_trait::async_trait]
    impl proctor_mint::aws::RawHttp for FakeSts {
        async fn post_form_raw(
            &self,
            _url: &str,
            _form: &[(String, String)],
        ) -> Result<String, proctor_mint::MintError> {
            Ok(r#"<r><Credentials><AccessKeyId>TKID_LIVE</AccessKeyId><SecretAccessKey>testsecretval</SecretAccessKey><SessionToken>testsessionval</SessionToken><Expiration>2026-07-12T12:00:00Z</Expiration></Credentials></r>"#.to_string())
        }
    }

    #[tokio::test]
    async fn run_routes_to_aws_minter_and_composes_multifield() {
        let items = vec![ItemRef {
            id: "itm_aws".into(),
            label: "AWS".into(),
            bound_origins: vec![],
            mintable: true,
        }];
        let mut secrets = HashMap::new();
        secrets.insert("itm_aws".to_string(), "held-oidc-jwt".to_string());
        let mut providers = HashMap::new();
        providers.insert("itm_aws".to_string(), "aws".to_string());

        let mut reg = Registry::new();
        reg.insert(
            toml::from_str(
                r#"
                id = "aws"
                mint = "aws-sts"
                commands = ["sh"]
                allow_shell = true
                read_patterns = ['\becho\b']
                [env_map]
                access_key_id = "AWS_ACCESS_KEY_ID"
                secret_access_key = "AWS_SECRET_ACCESS_KEY"
                session_token = "AWS_SESSION_TOKEN"
            "#,
            )
            .unwrap(),
        )
        .unwrap();

        let mut minters: HashMap<String, Arc<dyn Minter>> = HashMap::new();
        minters.insert(
            "aws-sts".into(),
            Arc::new(AwsWebIdentityMinter::new("arn:aws:iam::1:role/x", FakeSts)),
        );

        let server = ProctorServer::with(
            items,
            secrets,
            providers,
            Arc::new(MockMinter),
            minters,
            Arc::new(MockExecutor),
            Arc::new(reg),
            Isolation::None,
            &[],
            None,
        );

        let args = RunCommandArgs {
            item_id: "itm_aws".into(),
            program: "sh".into(),
            args: vec!["-c".into(), "echo key=$AWS_ACCESS_KEY_ID sess=$AWS_SESSION_TOKEN".into()],
            unattended: true,
        };
        let v = server.handle_run(args, &no_approve()).await;
        assert_eq!(v["decision"], "allow");
        // Routed to the AWS minter, whose JSON trio composed into the env_map.
        assert_eq!(v["credential_source"], "minted");
        let s = v.to_string();
        // The minted AWS creds reached the env (echoed), then were redacted.
        assert!(s.contains("REDACTED"), "expected redaction: {s}");
        assert!(!s.contains("TKID_LIVE"), "minted access key leaked!");
        assert!(!s.contains("testsessionval"), "minted session token leaked!");
    }

    #[tokio::test]
    async fn run_prefers_minted_credential_when_mintable() {
        // A mintable item → the broker mints a short-TTL token and injects THAT,
        // not the durable secret. (source: minted)
        let v = run_server_m(true)
            .handle_run(run_args("sh", &["-c", "echo hi"], true), &no_approve())
            .await;
        assert_eq!(v["decision"], "allow");
        assert_eq!(v["credential_source"], "minted");
    }

    #[tokio::test]
    async fn run_uses_stored_credential_when_not_mintable() {
        let v = run_server_m(false)
            .handle_run(run_args("sh", &["-c", "echo hi"], true), &no_approve())
            .await;
        assert_eq!(v["credential_source"], "stored");
    }

    #[tokio::test]
    async fn run_mutate_attended_requires_approval() {
        // Rejected → deny.
        let v = run_server()
            .handle_run(
                run_args("sh", &["-c", "echo delete"], false),
                &MockApprover(ApprovalOutcome::Rejected),
            )
            .await;
        assert_eq!(v["decision"], "deny");
        // Approved → runs.
        let v = run_server()
            .handle_run(
                run_args("sh", &["-c", "echo delete"], false),
                &MockApprover(ApprovalOutcome::Approved),
            )
            .await;
        assert_eq!(v["decision"], "allow");
        assert_eq!(v["ran"], true);
    }
}
