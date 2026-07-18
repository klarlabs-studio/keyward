//! Zero-knowledge sync server.
//!
//! A tiny HTTP API over [`proctor_sync`]. It stores an opaque sealed-vault blob
//! per account and never inspects it — no plaintext, master password, or Secret
//! Key ever reaches this process. Per-device bearer tokens map to accounts via
//! the [`AccountStore`], which stores only the SHA-256 hash of each token (a
//! breached registry yields no usable credentials). Versioning is optimistic
//! (`If-Match`), so a stale push gets 409 and must pull first.
//!
//! Config (env):
//!   PROCTOR_SYNC_ADDR             listen address (default 127.0.0.1:8787)
//!   PROCTOR_SYNC_PG              PostgreSQL URL → the scalable managed-cloud backend
//!                               (takes precedence over PROCTOR_SYNC_DIR)
//!   PROCTOR_SYNC_PG_POOL        Postgres pool size per replica (default 8)
//!   PROCTOR_STRIPE_WEBHOOK_SECRET  Stripe webhook signing secret; unset → webhook 503
//!   PROCTOR_SYNC_DIR              storage dir (FileStore + FileAccountStore); unset → in-memory
//!   PROCTOR_SYNC_TOKENS           optional pre-seed "token1:account1,token2:account2"
//!                                 (the registry is the source of truth; this is a fallback
//!                                 for tests/bootstrapping)
//!   PROCTOR_SYNC_TOKEN_TTL        optional device-token lifetime in seconds, applied on
//!                                 register / add-device (unset or 0 → tokens never expire,
//!                                 the backward-compatible default)
//!   PROCTOR_SYNC_RATELIMIT_PER_MIN  per-client-IP fixed-window rate limit for the
//!                                 abuse-prone unauthenticated/expensive endpoints
//!                                 (POST /v1/register, POST /v1/groups/{id}/invites).
//!                                 Unset → 30/min; 0 disables limiting. Over the limit → 429.
//!
//! Abuse controls: the endpoints above are rate-limited per client IP (see
//! `PROCTOR_SYNC_RATELIMIT_PER_MIN`) to close the DoS item in ADR-0004's threat
//! model (invite/register spam). The limiter is in-memory and dependency-free.
//!
//! Health + observability (no auth; keep /metrics cluster-internal):
//!   GET    /healthz           -> 200 {status:"ok"}   (liveness)
//!   GET    /readyz            -> 200 {status:"ok"}   (readiness)
//!   GET    /metrics           -> 200 Prometheus exposition (aggregate counters only)
//!
//! API (every response, including errors, carries permissive CORS headers):
//!   POST   /v1/register       -> 200 {account_id, device_token, device_id}    (no auth; rate-limited)
//!   POST   /v1/devices        -> 200 {device_token, device_id} (same account) | 401
//!   POST   /v1/devices/rotate -> 200 {device_token, device_id} (same device)  | 401
//!   GET    /v1/devices        -> 200 {devices:[{id,label,created_epoch,expires_epoch,current}]} | 401
//!   DELETE /v1/devices/{id}   -> 200 {revoked:true} | 404 | 401  (revoke a device)
//!   GET    /v1/vault          -> 200 + blob (+ X-Vault-Version) | 404 | 401
//!   PUT    /v1/vault          -> 200 + version (+ X-Vault-Version) | 409 (+ X-Vault-Version) | 401
//!   DELETE /v1/vault          -> 204 | 401  (erase this account's vault, idempotent)
//!   GET    /v1/account        -> 200 {account_id,plan,can_share,devices,device_limit} | 401
//!   POST   /v1/billing/webhook-> 200 (Stripe-signed; updates the account's plan) | 400 | 503
//!   OPTIONS *                 -> 204 (CORS preflight)
//!   (If-Match: <version> on PUT; omit for the first upload.)
//!
//! Family sharing — the zero-knowledge share-group relay (all auth'd):
//!   POST   /v1/groups                     -> 200 {group_id} (owner from body member)
//!   GET    /v1/groups/{id}                -> 200 {group_id,members,keys_version,content_version} | 403/404
//!   POST   /v1/groups/{id}/invites        -> 200 {invite_code,expires_epoch} (member; body {ttl_seconds}; rate-limited)
//!   POST   /v1/groups/{id}/members        -> 200 {joined:true} | 403 (invitee; body {code,member_id,name,public_key})
//!   GET    /v1/groups/{id}/keys           -> 200 + wrapped-keys blob (+ X-Vault-Version) | 404
//!   PUT    /v1/groups/{id}/keys           -> 200 + version | 409 (member; If-Match)
//!   GET    /v1/groups/{id}/vault          -> 200 + shared blob (+ X-Vault-Version) | 404
//!   PUT    /v1/groups/{id}/vault          -> 200 + version | 409 (member; If-Match)
//!   DELETE /v1/groups/{id}/members/{mid}  -> 200 {removed:true} | 403 (owner only)
//!   The server sees only public keys, opaque wrapped keys, opaque blobs, and
//!   hashed invite codes — never a vault key, master password, or Secret Key.

use hmac::{Hmac, Mac};
use proctor_sync::groups::{self, GroupInvite, GroupMember};
use proctor_sync::{
    AccountStore, FileAccountStore, FileShareGroupStore, FileStore, MemoryAccountStore,
    MemoryShareGroupStore, MemoryStore, Plan, RedeemOutcome, ShareGroupStore, SyncError, SyncStore,
    TokenIdentity,
};
use sha2::Sha256;
use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tiny_http::{Header, Method, Request, Response, Server};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Fixed-window in-memory rate limiter, keyed by client IP. Dependency-free and
/// thread-safe (a single `Mutex<HashMap>` — the request loop is not hot enough
/// to need sharded locking). Guards the abuse-prone unauthenticated/expensive
/// endpoints (register + invite mint) against the DoS vector in ADR-0004.
///
/// `limit` requests are allowed per `window_secs` per key; a `limit` of `0`
/// disables limiting entirely (every request is allowed).
struct RateLimiter {
    limit: u32,
    window_secs: u64,
    windows: Mutex<HashMap<String, Window>>,
}

/// One key's current fixed window: when it started and how many hits it has taken.
struct Window {
    start: u64,
    count: u32,
}

/// Opportunistic-sweep threshold: once the map exceeds this many keys, expired
/// windows are dropped on the next `allow` call so memory stays bounded even
/// under a churn of distinct source IPs.
const RATE_LIMIT_MAX_KEYS: usize = 100_000;

impl RateLimiter {
    /// A limiter allowing `limit` hits per 60s window (`limit == 0` disables it).
    fn per_minute(limit: u32) -> Self {
        RateLimiter {
            limit,
            window_secs: 60,
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Read `PROCTOR_SYNC_RATELIMIT_PER_MIN`. Unset/unparseable → 30/min (a
    /// sensible default that protects the managed cloud out of the box); an
    /// explicit `0` disables limiting.
    fn from_env() -> Self {
        let limit = std::env::var("PROCTOR_SYNC_RATELIMIT_PER_MIN")
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(30);
        RateLimiter::per_minute(limit)
    }

    /// Record a hit for `key` at `now`, returning `true` if it is within the
    /// limit and `false` if the limit is exceeded (the caller should 429).
    fn allow(&self, key: &str, now: u64) -> bool {
        if self.limit == 0 {
            return true;
        }
        let mut windows = self.windows.lock().unwrap_or_else(|p| p.into_inner());

        // Bound memory: drop windows that have fully expired before inserting more.
        if windows.len() > RATE_LIMIT_MAX_KEYS {
            let window_secs = self.window_secs;
            windows.retain(|_, w| now.saturating_sub(w.start) < window_secs);
        }

        let window = windows.entry(key.to_string()).or_insert(Window {
            start: now,
            count: 0,
        });
        if now.saturating_sub(window.start) >= self.window_secs {
            // The previous window has elapsed — start a fresh one.
            window.start = now;
            window.count = 0;
        }
        if window.count >= self.limit {
            return false;
        }
        window.count += 1;
        true
    }
}

/// Bundle of the two driven ports plus the optional static token pre-seed.
struct App {
    store: Box<dyn SyncStore + Send + Sync>,
    accounts: Box<dyn AccountStore + Send + Sync>,
    /// Share-group relay for family sharing (zero-knowledge: public keys + opaque
    /// wrapped keys + opaque content blob only).
    groups: Box<dyn ShareGroupStore + Send + Sync>,
    /// Optional pre-seeded token→account map. The registry is authoritative;
    /// this is only consulted as a fallback.
    seed_tokens: HashMap<String, String>,
    /// Optional device-token lifetime (seconds) applied on register/add-device.
    /// `None` → tokens never expire (backward-compatible default).
    token_ttl: Option<u64>,
    /// Per-client-IP rate limiter for the abuse-prone endpoints (register + invite mint).
    limiter: RateLimiter,
    /// Stripe webhook signing secret (`PROCTOR_STRIPE_WEBHOOK_SECRET`). `None`
    /// disables the billing webhook (returns 503).
    stripe_secret: Option<String>,
    /// Lightweight observability counters, exposed at `GET /metrics`.
    metrics: Metrics,
}

/// Minimal in-process metrics for a Prometheus scrape. Aggregate counts only — no
/// PII, no per-account data. Intended to be scraped cluster-internally, not via the
/// public ingress.
struct Metrics {
    requests_total: AtomicU64,
    start_epoch: u64,
    backend: &'static str,
}

/// Render the Prometheus exposition text. Pure, so it can be unit-tested.
fn render_metrics(requests_total: u64, uptime_secs: u64, backend: &str, version: &str) -> String {
    format!(
        "# HELP proctor_requests_total Total HTTP requests handled.\n\
         # TYPE proctor_requests_total counter\n\
         proctor_requests_total {requests_total}\n\
         # HELP proctor_uptime_seconds Seconds since server start.\n\
         # TYPE proctor_uptime_seconds gauge\n\
         proctor_uptime_seconds {uptime_secs}\n\
         # HELP proctor_build_info Static build/runtime info (always 1).\n\
         # TYPE proctor_build_info gauge\n\
         proctor_build_info{{backend=\"{backend}\",version=\"{version}\"}} 1\n"
    )
}

/// GET /metrics — Prometheus exposition (no auth; keep it cluster-internal).
fn handle_metrics(request: Request, app: &App) {
    let body = render_metrics(
        app.metrics.requests_total.load(Ordering::Relaxed),
        now_unix().saturating_sub(app.metrics.start_epoch),
        app.metrics.backend,
        env!("CARGO_PKG_VERSION"),
    );
    respond(request, text(&body, 200));
}

/// Read `PROCTOR_SYNC_TOKEN_TTL` as an optional lifetime in seconds. Unset,
/// unparseable, or `0` all mean "no expiry".
fn token_ttl_from_env() -> Option<u64> {
    std::env::var("PROCTOR_SYNC_TOKEN_TTL")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&ttl| ttl > 0)
}

/// Postgres connection-pool size per replica (`PROCTOR_SYNC_PG_POOL`, default 8).
fn pg_pool_size() -> u32 {
    std::env::var("PROCTOR_SYNC_PG_POOL")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(8)
}

/// The three driven ports as trait objects, so `main` can pick a backend at runtime.
type BoxedSyncStore = Box<dyn SyncStore + Send + Sync>;
type BoxedAccountStore = Box<dyn AccountStore + Send + Sync>;
type BoxedGroupStore = Box<dyn ShareGroupStore + Send + Sync>;

fn main() {
    let addr = std::env::var("PROCTOR_SYNC_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
    let seed_tokens = parse_tokens(&std::env::var("PROCTOR_SYNC_TOKENS").unwrap_or_default());
    let token_ttl = token_ttl_from_env();

    // Backend precedence: PostgreSQL (the managed-cloud, horizontally-scalable
    // backend) → filesystem (self-host) → in-memory (dev/tests).
    let pg_url = std::env::var("PROCTOR_SYNC_PG").unwrap_or_default();
    let (store, accounts, groups, backend): (
        BoxedSyncStore,
        BoxedAccountStore,
        BoxedGroupStore,
        &str,
    ) = if !pg_url.is_empty() {
        let pool = proctor_sync_postgres::connect(&pg_url, pg_pool_size()).unwrap_or_else(|e| {
            eprintln!("error: cannot connect to PROCTOR_SYNC_PG: {e}");
            std::process::exit(1);
        });
        (
            Box::new(proctor_sync_postgres::PostgresSyncStore::new(pool.clone())),
            Box::new(proctor_sync_postgres::PostgresAccountStore::new(
                pool.clone(),
            )),
            Box::new(proctor_sync_postgres::PostgresShareGroupStore::new(pool)),
            "postgres",
        )
    } else {
        match std::env::var("PROCTOR_SYNC_DIR") {
            Ok(dir) if !dir.is_empty() => (
                Box::new(FileStore::new(&dir)),
                Box::new(FileAccountStore::new(&dir)),
                Box::new(FileShareGroupStore::new(&dir)),
                "file",
            ),
            _ => (
                Box::new(MemoryStore::new()),
                Box::new(MemoryAccountStore::new()),
                Box::new(MemoryShareGroupStore::new()),
                "memory",
            ),
        }
    };
    eprintln!("proctor-sync-server backend: {backend}");

    let limiter = RateLimiter::from_env();

    let stripe_secret = std::env::var("PROCTOR_STRIPE_WEBHOOK_SECRET")
        .ok()
        .filter(|s| !s.trim().is_empty());

    let app = App {
        store,
        accounts,
        groups,
        seed_tokens,
        token_ttl,
        limiter,
        stripe_secret,
        metrics: Metrics {
            requests_total: AtomicU64::new(0),
            start_epoch: now_unix(),
            backend,
        },
    };

    let server = Server::http(&addr).unwrap_or_else(|e| {
        eprintln!("error: cannot bind {addr}: {e}");
        std::process::exit(1);
    });
    eprintln!(
        "proctor-sync-server listening on {addr} ({} pre-seeded token(s), token ttl: {}, rate limit: {})",
        app.seed_tokens.len(),
        match app.token_ttl {
            Some(ttl) => format!("{ttl}s"),
            None => "none".to_string(),
        },
        match app.limiter.limit {
            0 => "disabled".to_string(),
            n => format!("{n}/min per IP"),
        }
    );

    for request in server.incoming_requests() {
        handle(request, &app);
    }
}

/// Parse `token:account,token:account` into a token→account map.
fn parse_tokens(spec: &str) -> HashMap<String, String> {
    spec.split(',')
        .filter_map(|pair| pair.split_once(':'))
        .filter(|(t, a)| !t.is_empty() && !a.is_empty())
        .map(|(t, a)| (t.trim().to_string(), a.trim().to_string()))
        .collect()
}

/// The permissive CORS headers every response must carry so the browser app can
/// call the API cross-origin.
fn cors_headers() -> [Header; 4] {
    let h = |name: &str, value: &str| {
        Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("valid header")
    };
    [
        h("Access-Control-Allow-Origin", "*"),
        h(
            "Access-Control-Allow-Headers",
            "Authorization, If-Match, Content-Type",
        ),
        h("Access-Control-Expose-Headers", "X-Vault-Version"),
        h(
            "Access-Control-Allow-Methods",
            "GET, PUT, POST, DELETE, OPTIONS",
        ),
    ]
}

/// Attach the CORS headers to any response.
fn with_cors<R: Read>(mut resp: Response<R>) -> Response<R> {
    for header in cors_headers() {
        resp = resp.with_header(header);
    }
    resp
}

/// Respond with CORS headers applied. Swallows the send error like the rest of
/// the handlers (a dropped client is not our problem).
fn respond<R: Read>(request: Request, resp: Response<R>) {
    let _ = request.respond(with_cors(resp));
}

fn text(body: &str, status: u16) -> Response<Cursor<Vec<u8>>> {
    Response::from_string(body).with_status_code(status)
}

fn json(body: String, status: u16) -> Response<Cursor<Vec<u8>>> {
    let ct =
        Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("valid header");
    Response::from_string(body)
        .with_status_code(status)
        .with_header(ct)
}

/// Extract the raw bearer token from an `Authorization: Bearer <token>` header.
fn bearer_token(request: &Request) -> Option<String> {
    let auth = request.headers().iter().find(|h| {
        h.field
            .as_str()
            .as_str()
            .eq_ignore_ascii_case("authorization")
    })?;
    auth.value
        .as_str()
        .strip_prefix("Bearer ")
        .map(|t| t.trim().to_string())
}

/// Resolve a request's bearer token to an account + device. The registry is
/// authoritative; the static pre-seed map is a fallback for tests (no device id).
fn identity_for(request: &Request, app: &App) -> Option<TokenIdentity> {
    let token = bearer_token(request)?;
    if let Ok(Some(identity)) = app.accounts.resolve_token(&token, now_unix()) {
        return Some(identity);
    }
    app.seed_tokens.get(&token).map(|account_id| TokenIdentity {
        account_id: account_id.clone(),
        device_id: String::new(),
    })
}

/// Client IP (without the ephemeral port) for rate-limit keying. Falls back to a
/// shared `"unknown"` bucket if the peer address is unavailable (e.g. a Unix
/// socket) so such callers are still collectively bounded rather than unlimited.
fn client_ip(request: &Request) -> String {
    request
        .remote_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Whether this request should be rejected with 429. Records the hit against the
/// caller's IP; returns `true` when the per-IP limit is exceeded.
fn rate_limited(request: &Request, app: &App) -> bool {
    !app.limiter.allow(&client_ip(request), now_unix())
}

fn if_match(request: &Request) -> Option<u64> {
    request
        .headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case("if-match"))
        .and_then(|h| h.value.as_str().trim().parse::<u64>().ok())
}

fn version_header(version: u64) -> Header {
    Header::from_bytes(&b"X-Vault-Version"[..], version.to_string().as_bytes())
        .expect("valid header")
}

fn handle(request: Request, app: &App) {
    let method = request.method().clone();
    let url = request.url().to_string();

    // CORS preflight: answer any path/method probe up front.
    if method == Method::Options {
        respond(request, text("", 204));
        return;
    }

    // Health probes — no auth, no rate limit, so k8s liveness/readiness never
    // gets throttled or blocked. Answered before the versioned API.
    if method == Method::Get && (url == "/healthz" || url == "/readyz") {
        respond(request, json(r#"{"status":"ok"}"#.to_string(), 200));
        return;
    }

    // Prometheus scrape — aggregate counters only, no auth (keep cluster-internal).
    if method == Method::Get && url == "/metrics" {
        handle_metrics(request, app);
        return;
    }

    // Count every application request (health/metrics/preflight excluded above).
    app.metrics.requests_total.fetch_add(1, Ordering::Relaxed);

    match (&method, url.as_str()) {
        (Method::Post, "/v1/register") => {
            if rate_limited(&request, app) {
                respond(
                    request,
                    text("rate limit exceeded — try again shortly", 429),
                );
            } else {
                handle_register(request, app);
            }
        }
        (Method::Post, "/v1/devices/rotate") => handle_rotate_device(request, app),
        (Method::Post, "/v1/devices") => handle_add_device(request, app),
        (Method::Get, "/v1/devices") => handle_list_devices(request, app),
        (Method::Delete, path) if path.starts_with("/v1/devices/") => {
            let device_id = path.trim_start_matches("/v1/devices/").to_string();
            handle_revoke_device(request, app, &device_id);
        }
        (Method::Delete, "/v1/vault") => handle_delete_vault(request, app),
        (_, "/v1/vault") => handle_vault(request, app, method, &url),
        (Method::Get, "/v1/account") => handle_account(request, app),
        (Method::Post, "/v1/billing/webhook") => handle_billing_webhook(request, app),
        (_, path) if path == "/v1/groups" || path.starts_with("/v1/groups/") => {
            handle_groups(request, app, method, &url);
        }
        _ => respond(request, text("not found", 404)),
    }
}

/// Read a small JSON request body into a `Value`, tolerating an empty/absent body.
fn read_body_json(request: &mut Request) -> serde_json::Value {
    let mut body = Vec::new();
    let _ = request.as_reader().read_to_end(&mut body);
    serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null)
}

/// A string field from a parsed body, or `None`.
fn str_field(body: &serde_json::Value, field: &str) -> Option<String> {
    body.get(field).and_then(|e| e.as_str()).map(str::to_string)
}

/// POST /v1/register — no auth. Optional JSON body `{"email":"...","label":"..."}`.
fn handle_register(mut request: Request, app: &App) {
    let body = read_body_json(&mut request);
    let email = str_field(&body, "email");
    let label = str_field(&body, "label").unwrap_or_else(|| "This device".to_string());

    match app
        .accounts
        .register(email.as_deref(), &label, now_unix(), app.token_ttl)
    {
        Ok(account) => {
            eprintln!("POST /v1/register -> 200 account={}", account.account_id);
            let body = serde_json::json!({
                "account_id": account.account_id,
                "device_token": account.device_token,
                "device_id": account.device_id,
            })
            .to_string();
            respond(request, json(body, 200));
        }
        Err(e) => respond_500(request, &e),
    }
}

/// POST /v1/devices — auth. Mints a new device+token for the SAME account.
fn handle_add_device(mut request: Request, app: &App) {
    let token = match bearer_token(&request) {
        Some(t) => t,
        None => {
            respond(request, text("unauthorized", 401));
            return;
        }
    };
    let label = str_field(&read_body_json(&mut request), "label")
        .unwrap_or_else(|| "New device".to_string());

    // Entitlement: the free plan caps the device count. Resolve the caller's
    // account and refuse (402) if adding would exceed the plan's limit.
    if let Ok(Some(identity)) = app.accounts.resolve_token(&token, now_unix()) {
        if let Ok(plan) = app.accounts.get_plan(&identity.account_id) {
            if let Some(limit) = plan.device_limit() {
                let count = app
                    .accounts
                    .list_devices(&identity.account_id)
                    .map(|d| d.len())
                    .unwrap_or(0);
                if count >= limit {
                    respond(
                        request,
                        text(
                            "device limit reached on the free plan — upgrade to add more devices",
                            402,
                        ),
                    );
                    return;
                }
            }
        }
    }

    match app
        .accounts
        .add_device(&token, &label, now_unix(), app.token_ttl)
    {
        Ok(Some(account)) => {
            eprintln!(
                "POST /v1/devices -> 200 (new device for account={})",
                account.account_id
            );
            let body = serde_json::json!({
                "device_token": account.device_token,
                "device_id": account.device_id,
            })
            .to_string();
            respond(request, json(body, 200));
        }
        Ok(None) => respond(request, text("unauthorized", 401)),
        Err(e) => respond_500(request, &e),
    }
}

/// POST /v1/devices/rotate — auth. Issue a fresh token for the SAME device that
/// the presented token belongs to; the presented (old) token stops working. 401
/// if it is unknown or expired.
fn handle_rotate_device(request: Request, app: &App) {
    let token = match bearer_token(&request) {
        Some(t) => t,
        None => {
            respond(request, text("unauthorized", 401));
            return;
        }
    };
    match app.accounts.rotate_token(&token, now_unix()) {
        Ok(Some(account)) => {
            eprintln!(
                "POST /v1/devices/rotate -> 200 (rotated device={} account={})",
                account.device_id, account.account_id
            );
            let body = serde_json::json!({
                "device_token": account.device_token,
                "device_id": account.device_id,
            })
            .to_string();
            respond(request, json(body, 200));
        }
        Ok(None) => respond(request, text("unauthorized", 401)),
        Err(e) => respond_500(request, &e),
    }
}

/// GET /v1/devices — auth. List the account's devices (no secrets), flagging the
/// one making this request as `current`.
fn handle_list_devices(request: Request, app: &App) {
    let identity = match identity_for(&request, app) {
        Some(i) => i,
        None => {
            respond(request, text("unauthorized", 401));
            return;
        }
    };
    match app.accounts.list_devices(&identity.account_id) {
        Ok(devices) => {
            let items: Vec<serde_json::Value> = devices
                .iter()
                .map(|d| {
                    serde_json::json!({
                        "id": d.id,
                        "label": d.label,
                        "created_epoch": d.created_epoch,
                        "current": d.id == identity.device_id,
                    })
                })
                .collect();
            let body = serde_json::json!({ "devices": items }).to_string();
            respond(request, json(body, 200));
        }
        Err(e) => respond_500(request, &e),
    }
}

/// DELETE /v1/devices/{id} — auth. Revoke a device of the caller's OWN account
/// (you can only manage your own devices).
fn handle_revoke_device(request: Request, app: &App, device_id: &str) {
    let identity = match identity_for(&request, app) {
        Some(i) => i,
        None => {
            respond(request, text("unauthorized", 401));
            return;
        }
    };
    match app.accounts.revoke_device(&identity.account_id, device_id) {
        Ok(true) => {
            eprintln!("DELETE /v1/devices/{device_id} -> 200 (revoked)");
            respond(request, json(r#"{"revoked":true}"#.to_string(), 200));
        }
        Ok(false) => respond(request, text("no such device", 404)),
        Err(e) => respond_500(request, &e),
    }
}

/// GET/PUT /v1/vault — auth. Zero-knowledge blob get/put with optimistic
/// concurrency; the blob is never logged or inspected.
fn handle_vault(mut request: Request, app: &App, method: Method, url: &str) {
    let account = match identity_for(&request, app) {
        Some(i) => i.account_id,
        None => {
            eprintln!("{method} {url} -> 401 (bad/missing token)");
            respond(request, text("unauthorized", 401));
            return;
        }
    };

    match method {
        Method::Get => match app.store.get(&account) {
            Ok(Some(env)) => {
                eprintln!("GET {url} account={account} -> 200 v{}", env.version);
                let resp = Response::from_data(env.blob)
                    .with_status_code(200)
                    .with_header(version_header(env.version));
                respond(request, resp);
            }
            Ok(None) => {
                eprintln!("GET {url} account={account} -> 404 (no vault yet)");
                respond(request, text("no vault", 404));
            }
            Err(e) => respond_500(request, &e),
        },
        Method::Put => {
            let expected = if_match(&request);
            let mut blob = Vec::new();
            if request.as_reader().read_to_end(&mut blob).is_err() {
                respond(request, text("bad body", 400));
                return;
            }
            // NOTE: the blob is never logged or inspected — zero knowledge.
            match app.store.put(&account, expected, blob) {
                Ok(version) => {
                    eprintln!("PUT {url} account={account} -> 200 v{version}");
                    let resp = Response::from_string(version.to_string())
                        .with_status_code(200)
                        .with_header(version_header(version));
                    respond(request, resp);
                }
                Err(SyncError::Conflict { server_version }) => {
                    eprintln!("PUT {url} account={account} -> 409 (server v{server_version})");
                    let resp = Response::from_string("version conflict — pull first")
                        .with_status_code(409)
                        .with_header(version_header(server_version));
                    respond(request, resp);
                }
                Err(e) => respond_500(request, &e),
            }
        }
        _ => respond(request, text("method not allowed", 405)),
    }
}

/// DELETE /v1/vault — auth. Erase the caller's account vault (idempotent — a
/// missing vault still returns 204). Zero-knowledge: we delete opaque bytes.
fn handle_delete_vault(request: Request, app: &App) {
    let account = match identity_for(&request, app) {
        Some(i) => i.account_id,
        None => {
            eprintln!("DELETE /v1/vault -> 401 (bad/missing token)");
            respond(request, text("unauthorized", 401));
            return;
        }
    };
    match app.store.delete(&account) {
        Ok(()) => {
            eprintln!("DELETE /v1/vault account={account} -> 204 (erased)");
            respond(request, text("", 204));
        }
        Err(e) => respond_500(request, &e),
    }
}

/// Which versioned blob of a group a `/keys` or `/vault` request targets.
#[derive(Clone, Copy)]
enum Blob {
    Keys,
    Content,
}

/// Dispatch every `/v1/groups...` route. All group routes require a valid token;
/// finer authorization (member vs. owner) is enforced per-handler against the
/// group's public membership directory.
fn handle_groups(request: Request, app: &App, method: Method, url: &str) {
    let account = match identity_for(&request, app) {
        Some(i) => i.account_id,
        None => {
            respond(request, text("unauthorized", 401));
            return;
        }
    };
    let path = url.split('?').next().unwrap_or(url);

    if path == "/v1/groups" {
        match method {
            Method::Post => handle_group_create(request, app, &account),
            _ => respond(request, text("method not allowed", 405)),
        }
        return;
    }

    let rest = path.trim_start_matches("/v1/groups/");
    let segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    match (segs.as_slice(), &method) {
        ([id], Method::Get) => handle_group_get(request, app, &account, id),
        ([id, "invites"], Method::Post) => {
            if rate_limited(&request, app) {
                respond(
                    request,
                    text("rate limit exceeded — try again shortly", 429),
                );
            } else {
                handle_group_invite(request, app, &account, id);
            }
        }
        ([id, "members"], Method::Post) => handle_group_join(request, app, &account, id),
        ([id, "members", mid], Method::Delete) => {
            handle_group_remove(request, app, &account, id, mid)
        }
        ([id, "keys"], _) => handle_group_blob(request, app, &account, id, method, Blob::Keys),
        ([id, "vault"], _) => handle_group_blob(request, app, &account, id, method, Blob::Content),
        _ => respond(request, text("not found", 404)),
    }
}

/// POST /v1/groups — create a group; the caller becomes its owner. Body:
/// `{member_id, name, public_key}` (the owner's public member identity).
fn handle_group_create(mut request: Request, app: &App, account: &str) {
    // Entitlement: creating (owning) a family vault requires the Family plan. Members
    // who *join* a vault do not need their own paid plan — the owner's plan covers them.
    if !app
        .accounts
        .get_plan(account)
        .map(|p| p.can_share())
        .unwrap_or(false)
    {
        respond(
            request,
            text(
                "family sharing requires the Family plan — upgrade to create a family vault",
                402,
            ),
        );
        return;
    }

    let body = read_body_json(&mut request);
    let (Some(member_id), Some(public_key)) = (
        str_field(&body, "member_id"),
        str_field(&body, "public_key"),
    ) else {
        respond(request, text("member_id and public_key required", 400));
        return;
    };
    let owner = GroupMember {
        member_id,
        account_id: account.to_string(),
        name: str_field(&body, "name").unwrap_or_default(),
        public_key,
        is_owner: true,
        added_epoch: now_unix(),
    };
    let group_id = groups::new_id();
    match app.groups.create(&group_id, owner) {
        Ok(_) => {
            eprintln!("POST /v1/groups -> 200 group={group_id} owner_account={account}");
            respond(
                request,
                json(serde_json::json!({ "group_id": group_id }).to_string(), 200),
            );
        }
        Err(e) => respond_500(request, &e),
    }
}

/// GET /v1/groups/{id} — members + versions (members only).
fn handle_group_get(request: Request, app: &App, account: &str, id: &str) {
    let group = match app.groups.get(id) {
        Ok(Some(g)) => g,
        Ok(None) => {
            respond(request, text("no such group", 404));
            return;
        }
        Err(e) => {
            respond_500(request, &e);
            return;
        }
    };
    if !group.is_member(account) {
        respond(request, text("not a member", 403));
        return;
    }
    let body = serde_json::json!({
        "group_id": group.group_id,
        "members": group.members,
        "keys_version": group.keys_version,
        "content_version": group.content_version,
    })
    .to_string();
    respond(request, json(body, 200));
}

/// POST /v1/groups/{id}/invites — mint a single-use, TTL'd invite (members only).
/// Body: `{ttl_seconds?}`. Returns the plaintext `invite_code` (shown once); the
/// server keeps only its hash.
fn handle_group_invite(mut request: Request, app: &App, account: &str, id: &str) {
    // Membership check.
    match app.groups.get(id) {
        Ok(Some(g)) if g.is_member(account) => {}
        Ok(Some(_)) => {
            respond(request, text("not a member", 403));
            return;
        }
        Ok(None) => {
            respond(request, text("no such group", 404));
            return;
        }
        Err(e) => {
            respond_500(request, &e);
            return;
        }
    }
    let ttl = read_body_json(&mut request)
        .get("ttl_seconds")
        .and_then(|v| v.as_u64())
        .filter(|&t| t > 0)
        .unwrap_or(24 * 60 * 60); // default: 24h
    let code = groups::new_id();
    let now = now_unix();
    let invite = GroupInvite {
        code_hash: groups::hash_code(&code),
        created_epoch: now,
        expires_epoch: now.saturating_add(ttl),
        redeemed_by: None,
    };
    match app.groups.add_invite(id, invite) {
        Ok(true) => {
            eprintln!("POST /v1/groups/{id}/invites -> 200 (minted, ttl {ttl}s)");
            let body = serde_json::json!({
                "invite_code": code,
                "expires_epoch": now.saturating_add(ttl),
            })
            .to_string();
            respond(request, json(body, 200));
        }
        Ok(false) => respond(request, text("no such group", 404)),
        Err(e) => respond_500(request, &e),
    }
}

/// POST /v1/groups/{id}/members — redeem an invite and join. Body:
/// `{code, member_id, name, public_key}`. The caller joins as their own account.
fn handle_group_join(mut request: Request, app: &App, account: &str, id: &str) {
    let body = read_body_json(&mut request);
    let (Some(code), Some(member_id), Some(public_key)) = (
        str_field(&body, "code"),
        str_field(&body, "member_id"),
        str_field(&body, "public_key"),
    ) else {
        respond(
            request,
            text("code, member_id and public_key required", 400),
        );
        return;
    };
    let new_member = GroupMember {
        member_id,
        account_id: account.to_string(),
        name: str_field(&body, "name").unwrap_or_default(),
        public_key,
        is_owner: false,
        added_epoch: now_unix(),
    };
    match app
        .groups
        .redeem_invite(id, &groups::hash_code(&code), new_member, now_unix())
    {
        Ok(RedeemOutcome::Added) => {
            eprintln!("POST /v1/groups/{id}/members -> 200 (account={account} joined)");
            respond(request, json(r#"{"joined":true}"#.to_string(), 200));
        }
        Ok(RedeemOutcome::Expired) => respond(request, text("invite expired", 403)),
        Ok(RedeemOutcome::InvalidOrUsed) => {
            respond(request, text("invalid or already-used invite", 403))
        }
        Ok(RedeemOutcome::NoSuchGroup) => respond(request, text("no such group", 404)),
        Err(e) => respond_500(request, &e),
    }
}

/// DELETE /v1/groups/{id}/members/{mid} — remove a member (owner only). True
/// revocation also requires the client to rotate the vault key and re-push
/// `/keys` + `/vault`; the server only drops the directory entry.
fn handle_group_remove(request: Request, app: &App, account: &str, id: &str, member_id: &str) {
    match app.groups.get(id) {
        Ok(Some(g)) if g.is_owner(account) => {}
        Ok(Some(_)) => {
            respond(request, text("owner only", 403));
            return;
        }
        Ok(None) => {
            respond(request, text("no such group", 404));
            return;
        }
        Err(e) => {
            respond_500(request, &e);
            return;
        }
    }
    match app.groups.remove_member(id, member_id) {
        Ok(true) => {
            eprintln!("DELETE /v1/groups/{id}/members/{member_id} -> 200 (removed)");
            respond(request, json(r#"{"removed":true}"#.to_string(), 200));
        }
        Ok(false) => respond(request, text("no such member", 404)),
        Err(e) => respond_500(request, &e),
    }
}

/// GET/PUT the group's wrapped-keys or shared-content blob (members only), with
/// the same optimistic-concurrency (`If-Match` + `X-Vault-Version`) contract as
/// the personal vault. The blobs are opaque — never logged or inspected.
fn handle_group_blob(
    mut request: Request,
    app: &App,
    account: &str,
    id: &str,
    method: Method,
    which: Blob,
) {
    let group = match app.groups.get(id) {
        Ok(Some(g)) => g,
        Ok(None) => {
            respond(request, text("no such group", 404));
            return;
        }
        Err(e) => {
            respond_500(request, &e);
            return;
        }
    };
    if !group.is_member(account) {
        respond(request, text("not a member", 403));
        return;
    }

    match method {
        Method::Get => {
            let (blob, version) = match which {
                Blob::Keys => (group.wrapped_keys, group.keys_version),
                Blob::Content => (group.content, group.content_version),
            };
            if version == 0 {
                respond(request, text("nothing uploaded yet", 404));
                return;
            }
            let resp = Response::from_data(blob)
                .with_status_code(200)
                .with_header(version_header(version));
            respond(request, resp);
        }
        Method::Put => {
            let expected = if_match(&request);
            let mut blob = Vec::new();
            if request.as_reader().read_to_end(&mut blob).is_err() {
                respond(request, text("bad body", 400));
                return;
            }
            let result = match which {
                Blob::Keys => app.groups.put_keys(id, expected, blob),
                Blob::Content => app.groups.put_content(id, expected, blob),
            };
            match result {
                Ok(version) => {
                    let resp = Response::from_string(version.to_string())
                        .with_status_code(200)
                        .with_header(version_header(version));
                    respond(request, resp);
                }
                Err(SyncError::Conflict { server_version }) => {
                    let resp = Response::from_string("version conflict — pull first")
                        .with_status_code(409)
                        .with_header(version_header(server_version));
                    respond(request, resp);
                }
                Err(e) => respond_500(request, &e),
            }
        }
        _ => respond(request, text("method not allowed", 405)),
    }
}

/// GET /v1/account — auth. The caller's plan + device usage (the entitlements
/// view the client uses to reflect the tier and gate paid features in the UI).
fn handle_account(request: Request, app: &App) {
    let account = match identity_for(&request, app) {
        Some(i) => i.account_id,
        None => {
            respond(request, text("unauthorized", 401));
            return;
        }
    };
    let plan = app.accounts.get_plan(&account).unwrap_or(Plan::Free);
    let devices = app
        .accounts
        .list_devices(&account)
        .map(|d| d.len())
        .unwrap_or(0);
    let body = serde_json::json!({
        "account_id": account,
        "plan": plan.as_str(),
        "can_share": plan.can_share(),
        "devices": devices,
        "device_limit": plan.device_limit(),
    })
    .to_string();
    respond(request, json(body, 200));
}

/// POST /v1/billing/webhook — Stripe webhook. Verifies the `Stripe-Signature`
/// HMAC over the raw body, then maps a subscription event to a plan and updates the
/// account (metadata plane only — zero-knowledge is untouched). 503 if no signing
/// secret is configured, 400 on a bad signature.
fn handle_billing_webhook(mut request: Request, app: &App) {
    let Some(secret) = app.stripe_secret.clone() else {
        respond(request, text("billing webhook not configured", 503));
        return;
    };
    let sig = request
        .headers()
        .iter()
        .find(|h| {
            h.field
                .as_str()
                .as_str()
                .eq_ignore_ascii_case("stripe-signature")
        })
        .map(|h| h.value.as_str().to_string())
        .unwrap_or_default();
    let mut body = String::new();
    if request.as_reader().read_to_string(&mut body).is_err() {
        respond(request, text("bad body", 400));
        return;
    }
    if !verify_stripe_signature(&body, &sig, &secret, now_unix(), 300) {
        respond(request, text("invalid signature", 400));
        return;
    }

    let event: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    let kind = event.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let obj = event
        .get("data")
        .and_then(|d| d.get("object"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let metadata = obj.get("metadata");
    let account_id = metadata
        .and_then(|m| m.get("account_id"))
        .and_then(|v| v.as_str());
    let Some(account_id) = account_id else {
        // No account to map — acknowledge so Stripe stops retrying.
        respond(
            request,
            json(r#"{"received":true,"applied":false}"#.to_string(), 200),
        );
        return;
    };
    // A cancelled subscription drops to Free; otherwise the plan is carried in the
    // checkout/subscription metadata (set by the client at checkout).
    let plan = if kind == "customer.subscription.deleted" {
        Plan::Free
    } else {
        Plan::parse(
            metadata
                .and_then(|m| m.get("plan"))
                .and_then(|v| v.as_str())
                .unwrap_or("free"),
        )
    };
    let applied = app.accounts.set_plan(account_id, plan).unwrap_or(false);
    eprintln!(
        "POST /v1/billing/webhook -> 200 (event={kind} account={account_id} plan={} applied={applied})",
        plan.as_str()
    );
    respond(
        request,
        json(format!(r#"{{"received":true,"applied":{applied}}}"#), 200),
    );
}

/// Verify a Stripe `Stripe-Signature` header over the raw payload. Header format is
/// `t=<unix>,v1=<hex-hmac>[,v1=...]`; the signed content is `"{t}.{payload}"`,
/// HMAC-SHA256'd with the signing secret and constant-time compared. Timestamps
/// outside `tolerance` seconds of `now` are rejected (replay protection) when
/// `tolerance > 0`.
fn verify_stripe_signature(
    payload: &str,
    sig_header: &str,
    secret: &str,
    now: u64,
    tolerance: u64,
) -> bool {
    let mut timestamp: Option<u64> = None;
    let mut signatures: Vec<&str> = Vec::new();
    for part in sig_header.split(',') {
        let part = part.trim();
        if let Some(t) = part.strip_prefix("t=") {
            timestamp = t.parse().ok();
        } else if let Some(v) = part.strip_prefix("v1=") {
            signatures.push(v);
        }
    }
    let Some(t) = timestamp else { return false };
    if signatures.is_empty() {
        return false;
    }
    if tolerance > 0 && now.abs_diff(t) > tolerance {
        return false;
    }
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(format!("{t}.{payload}").as_bytes());
    let tag = mac.finalize().into_bytes();
    let expected: String = tag.iter().map(|b| format!("{b:02x}")).collect();
    signatures
        .iter()
        .any(|s| constant_time_eq(s.as_bytes(), expected.as_bytes()))
}

/// Length-checked constant-time byte comparison (avoids leaking match position).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn respond_500(request: Request, err: &SyncError) {
    eprintln!("error: {err}");
    respond(request, text("server error", 500));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Produce a valid `Stripe-Signature` header for `payload` at time `t`.
    fn sign(payload: &str, secret: &str, t: u64) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(format!("{t}.{payload}").as_bytes());
        let hex: String = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("t={t},v1={hex}")
    }

    #[test]
    fn stripe_signature_roundtrip_and_rejections() {
        let secret = "whsec_test";
        let payload = r#"{"type":"customer.subscription.updated"}"#;
        let now = 1_000_000;
        let header = sign(payload, secret, now);

        // A correctly signed, fresh payload verifies.
        assert!(verify_stripe_signature(payload, &header, secret, now, 300));
        // Within tolerance is fine.
        assert!(verify_stripe_signature(
            payload,
            &header,
            secret,
            now + 200,
            300
        ));

        // Tampered payload, wrong secret, stale timestamp, and a missing/garbage
        // header all fail.
        assert!(!verify_stripe_signature("{}", &header, secret, now, 300));
        assert!(!verify_stripe_signature(
            payload, &header, "wrong", now, 300
        ));
        assert!(!verify_stripe_signature(
            payload,
            &header,
            secret,
            now + 10_000,
            300
        ));
        assert!(!verify_stripe_signature(
            payload, "garbage", secret, now, 300
        ));
        assert!(!verify_stripe_signature(payload, "t=1", secret, now, 0));
    }

    #[test]
    fn metrics_render_is_valid_prometheus() {
        let out = render_metrics(42, 100, "postgres", "1.33.0");
        assert!(out.contains("proctor_requests_total 42\n"));
        assert!(out.contains("proctor_uptime_seconds 100\n"));
        assert!(out.contains("proctor_build_info{backend=\"postgres\",version=\"1.33.0\"} 1\n"));
        // Every metric is preceded by its HELP/TYPE lines.
        assert_eq!(out.matches("# TYPE").count(), 3);
    }

    #[test]
    fn constant_time_eq_matches_only_equal_slices() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn allows_up_to_the_limit_then_blocks_within_a_window() {
        let rl = RateLimiter::per_minute(3);
        // First three hits in the same second are allowed.
        assert!(rl.allow("1.2.3.4", 1000));
        assert!(rl.allow("1.2.3.4", 1000));
        assert!(rl.allow("1.2.3.4", 1005));
        // The fourth within the 60s window is blocked.
        assert!(!rl.allow("1.2.3.4", 1010));
        assert!(!rl.allow("1.2.3.4", 1059));
    }

    #[test]
    fn window_resets_after_it_elapses() {
        let rl = RateLimiter::per_minute(2);
        assert!(rl.allow("ip", 0));
        assert!(rl.allow("ip", 30));
        assert!(!rl.allow("ip", 59)); // still inside the first 60s window
                                      // At t=60 the window has elapsed → a fresh allowance.
        assert!(rl.allow("ip", 60));
        assert!(rl.allow("ip", 61));
        assert!(!rl.allow("ip", 62));
    }

    #[test]
    fn limits_are_per_key() {
        let rl = RateLimiter::per_minute(1);
        assert!(rl.allow("a", 0));
        assert!(!rl.allow("a", 0));
        // A different key has its own independent budget.
        assert!(rl.allow("b", 0));
        assert!(!rl.allow("b", 0));
    }

    #[test]
    fn zero_limit_disables_limiting() {
        let rl = RateLimiter::per_minute(0);
        for _ in 0..1000 {
            assert!(rl.allow("anyone", 0));
        }
    }

    #[test]
    fn expired_windows_are_swept_when_the_map_grows() {
        let rl = RateLimiter::per_minute(1);
        // Seed more than the sweep threshold of distinct, long-expired keys.
        for i in 0..=RATE_LIMIT_MAX_KEYS {
            rl.allow(&format!("k{i}"), 0);
        }
        // A hit far in the future triggers the opportunistic sweep; expired
        // entries are dropped so the map does not grow without bound.
        rl.allow("trigger", 10_000);
        let len = rl.windows.lock().unwrap().len();
        assert!(
            len <= 2,
            "expected stale windows to be swept, map still holds {len} entries"
        );
    }
}
