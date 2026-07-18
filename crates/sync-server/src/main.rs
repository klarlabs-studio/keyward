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
//!   PROCTOR_STRIPE_SECRET_KEY    Stripe API secret key (server-side only)
//!   PROCTOR_STRIPE_PRICE_FAMILY  Stripe price id for the Family plan
//!                               (both required for POST /v1/billing/checkout; else 503)
//!   PROCTOR_STRIPE_SUCCESS_URL / PROCTOR_STRIPE_CANCEL_URL  post-checkout redirects
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
//!                               Includes the family-sharing funnel — registrations,
//!                               groups created, invites minted/redeemed/rejected (by
//!                               reason), key + content writes, members removed, and
//!                               paywall (402) denials — so we can see where real
//!                               families drop out. Counts only: no account, group,
//!                               member, or network identifiers are ever exposed.
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
//!   POST   /v1/billing/checkout-> 200 {url} (hosted Stripe Checkout session) | 401 | 502 | 503
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
//!   DELETE /v1/groups/{id}/members/{mid}  -> 200 {removed:true} | 403 (admin/owner; owners are never removable)
//!   POST   /v1/groups/{id}/members/{mid}/role -> 200 {role} | 403 (owner only; body {role})
//!   Roles: Owner > Admin > Member. Admin+ may invite and remove members; only an
//!   Owner may change roles. Unknown role names fail closed to Member.
//!   The server sees only public keys, opaque wrapped keys, opaque blobs, and
//!   hashed invite codes — never a vault key, master password, or Secret Key.

use hmac::{Hmac, Mac};
use proctor_sync::groups::{self, GroupInvite, GroupMember};
use proctor_sync::{
    AccountStore, FileAccountStore, FileShareGroupStore, FileStore, MemoryAccountStore,
    MemoryShareGroupStore, MemoryStore, Plan, RedeemOutcome, Role, ShareGroupStore, SyncError,
    SyncStore, TokenIdentity,
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
    /// Stripe Checkout config for `POST /v1/billing/checkout`. `None` (missing
    /// secret key or Family price id) disables checkout (returns 503).
    stripe_checkout: Option<StripeCheckout>,
    /// Lightweight observability counters, exposed at `GET /metrics`.
    metrics: Metrics,
}

/// Stripe Checkout configuration. The server creates a subscription Checkout
/// session server-side (the secret key never reaches the client) and returns the
/// hosted URL for the app to redirect to.
struct StripeCheckout {
    secret_key: String,
    price_family: String,
    success_url: String,
    cancel_url: String,
}

/// Minimal in-process metrics for a Prometheus scrape. Aggregate counts only — no
/// PII, no per-account data. Intended to be scraped cluster-internally, not via the
/// public ingress.
struct Metrics {
    requests_total: AtomicU64,
    start_epoch: u64,
    backend: &'static str,
    /// The family-sharing funnel (see [`Funnel`]).
    funnel: Funnel,
}

/// The family-sharing funnel. A request counter tells us the server is *busy*; it
/// says nothing about whether a family actually ends up sharing anything. These
/// count each step of the real journey — register → create a group → mint an invite
/// → redeem it → grant keys → store a shared item — plus the two places people fall
/// out (invite rejections and paywall denials), so a drop-off is visible instead of
/// inferred.
///
/// Deliberately aggregate: every counter is a plain total with no account, group,
/// member, device, or IP dimension. Metrics must never reconstruct the family graph
/// that the zero-knowledge design exists to hide.
#[derive(Default)]
struct Funnel {
    /// Funnel entry: an account exists at all.
    accounts_registered: AtomicU64,
    /// A family vault was created (the owner cleared the Family-plan gate).
    groups_created: AtomicU64,
    /// An invite was minted — intent to share, not yet a shared family.
    invites_minted: AtomicU64,
    /// An invite was actually redeemed: a second person is in the vault. The
    /// minted→redeemed gap is the core conversion of the whole feature.
    invites_redeemed: AtomicU64,
    /// Redemption failures, split by reason so we can tell a UX problem (codes
    /// mistyped/reused) from a latency problem (24h TTL ran out) from a plain bug.
    invites_rejected_invalid_or_used: AtomicU64,
    invites_rejected_expired: AtomicU64,
    invites_rejected_no_such_group: AtomicU64,
    /// A wrapped-keys push succeeded — a member was actually granted crypto access,
    /// or a key rotation landed. Joining without this is a half-finished share.
    group_keys_writes: AtomicU64,
    /// A shared-content push succeeded — someone actually put an item in the family
    /// vault. This is the "the feature delivered value" signal.
    group_content_writes: AtomicU64,
    /// A member was removed (offboarding works, and how often it happens).
    members_removed: AtomicU64,
    /// Paywall hits (402), split by which gate fired — how much demand the free
    /// tier is actually leaving on the table.
    entitlement_denied_device_limit: AtomicU64,
    entitlement_denied_family_plan: AtomicU64,
}

impl Funnel {
    /// Read every counter once, for rendering. Relaxed loads: each counter is
    /// independent and a scrape needs no cross-counter consistency.
    fn snapshot(&self) -> FunnelSnapshot {
        let load = |c: &AtomicU64| c.load(Ordering::Relaxed);
        FunnelSnapshot {
            accounts_registered: load(&self.accounts_registered),
            groups_created: load(&self.groups_created),
            invites_minted: load(&self.invites_minted),
            invites_redeemed: load(&self.invites_redeemed),
            invites_rejected_invalid_or_used: load(&self.invites_rejected_invalid_or_used),
            invites_rejected_expired: load(&self.invites_rejected_expired),
            invites_rejected_no_such_group: load(&self.invites_rejected_no_such_group),
            group_keys_writes: load(&self.group_keys_writes),
            group_content_writes: load(&self.group_content_writes),
            members_removed: load(&self.members_removed),
            entitlement_denied_device_limit: load(&self.entitlement_denied_device_limit),
            entitlement_denied_family_plan: load(&self.entitlement_denied_family_plan),
        }
    }
}

/// A point-in-time copy of [`Funnel`], so rendering stays a pure function of plain
/// values (and so the render signature stays a named type rather than a 12-tuple).
#[derive(Default, Clone, Copy)]
struct FunnelSnapshot {
    accounts_registered: u64,
    groups_created: u64,
    invites_minted: u64,
    invites_redeemed: u64,
    invites_rejected_invalid_or_used: u64,
    invites_rejected_expired: u64,
    invites_rejected_no_such_group: u64,
    group_keys_writes: u64,
    group_content_writes: u64,
    members_removed: u64,
    entitlement_denied_device_limit: u64,
    entitlement_denied_family_plan: u64,
}

/// Everything a scrape renders, as plain values.
struct MetricsSnapshot<'a> {
    requests_total: u64,
    uptime_secs: u64,
    backend: &'a str,
    version: &'a str,
    funnel: FunnelSnapshot,
}

/// Render the Prometheus exposition text. Pure, so it can be unit-tested.
fn render_metrics(m: &MetricsSnapshot) -> String {
    let MetricsSnapshot {
        requests_total,
        uptime_secs,
        backend,
        version,
        funnel: f,
    } = m;
    format!(
        "# HELP proctor_requests_total Total HTTP requests handled.\n\
         # TYPE proctor_requests_total counter\n\
         proctor_requests_total {requests_total}\n\
         # HELP proctor_uptime_seconds Seconds since server start.\n\
         # TYPE proctor_uptime_seconds gauge\n\
         proctor_uptime_seconds {uptime_secs}\n\
         # HELP proctor_build_info Static build/runtime info (always 1).\n\
         # TYPE proctor_build_info gauge\n\
         proctor_build_info{{backend=\"{backend}\",version=\"{version}\"}} 1\n\
         # HELP proctor_accounts_registered_total Accounts successfully registered.\n\
         # TYPE proctor_accounts_registered_total counter\n\
         proctor_accounts_registered_total {accounts_registered}\n\
         # HELP proctor_groups_created_total Family vaults successfully created.\n\
         # TYPE proctor_groups_created_total counter\n\
         proctor_groups_created_total {groups_created}\n\
         # HELP proctor_invites_minted_total Share invites successfully minted.\n\
         # TYPE proctor_invites_minted_total counter\n\
         proctor_invites_minted_total {invites_minted}\n\
         # HELP proctor_invites_redeemed_total Share invites successfully redeemed (a member joined).\n\
         # TYPE proctor_invites_redeemed_total counter\n\
         proctor_invites_redeemed_total {invites_redeemed}\n\
         # HELP proctor_invites_rejected_total Invite redemptions rejected, by reason.\n\
         # TYPE proctor_invites_rejected_total counter\n\
         proctor_invites_rejected_total{{reason=\"invalid_or_used\"}} {invalid_or_used}\n\
         proctor_invites_rejected_total{{reason=\"expired\"}} {expired}\n\
         proctor_invites_rejected_total{{reason=\"no_such_group\"}} {no_such_group}\n\
         # HELP proctor_group_keys_writes_total Wrapped-key blobs successfully written (access granted or rotated).\n\
         # TYPE proctor_group_keys_writes_total counter\n\
         proctor_group_keys_writes_total {group_keys_writes}\n\
         # HELP proctor_group_content_writes_total Shared-content blobs successfully written (an item was shared).\n\
         # TYPE proctor_group_content_writes_total counter\n\
         proctor_group_content_writes_total {group_content_writes}\n\
         # HELP proctor_members_removed_total Group members successfully removed.\n\
         # TYPE proctor_members_removed_total counter\n\
         proctor_members_removed_total {members_removed}\n\
         # HELP proctor_entitlement_denied_total Requests refused with 402 by an entitlement gate, by reason.\n\
         # TYPE proctor_entitlement_denied_total counter\n\
         proctor_entitlement_denied_total{{reason=\"device_limit\"}} {device_limit}\n\
         proctor_entitlement_denied_total{{reason=\"family_plan\"}} {family_plan}\n",
        accounts_registered = f.accounts_registered,
        groups_created = f.groups_created,
        invites_minted = f.invites_minted,
        invites_redeemed = f.invites_redeemed,
        invalid_or_used = f.invites_rejected_invalid_or_used,
        expired = f.invites_rejected_expired,
        no_such_group = f.invites_rejected_no_such_group,
        group_keys_writes = f.group_keys_writes,
        group_content_writes = f.group_content_writes,
        members_removed = f.members_removed,
        device_limit = f.entitlement_denied_device_limit,
        family_plan = f.entitlement_denied_family_plan,
    )
}

/// GET /metrics — Prometheus exposition (no auth; keep it cluster-internal).
fn handle_metrics(request: Request, app: &App) {
    let body = render_metrics(&MetricsSnapshot {
        requests_total: app.metrics.requests_total.load(Ordering::Relaxed),
        uptime_secs: now_unix().saturating_sub(app.metrics.start_epoch),
        backend: app.metrics.backend,
        version: env!("CARGO_PKG_VERSION"),
        funnel: app.metrics.funnel.snapshot(),
    });
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

    // Checkout needs both a secret key and a Family price id; otherwise it is off.
    let nonempty = |k: &str| std::env::var(k).ok().filter(|s| !s.trim().is_empty());
    let stripe_checkout = match (
        nonempty("PROCTOR_STRIPE_SECRET_KEY"),
        nonempty("PROCTOR_STRIPE_PRICE_FAMILY"),
    ) {
        (Some(secret_key), Some(price_family)) => Some(StripeCheckout {
            secret_key,
            price_family,
            success_url: nonempty("PROCTOR_STRIPE_SUCCESS_URL")
                .unwrap_or_else(|| "https://example.com/billing/success".to_string()),
            cancel_url: nonempty("PROCTOR_STRIPE_CANCEL_URL")
                .unwrap_or_else(|| "https://example.com/billing/cancel".to_string()),
        }),
        _ => None,
    };

    let app = App {
        store,
        accounts,
        groups,
        seed_tokens,
        token_ttl,
        limiter,
        stripe_secret,
        stripe_checkout,
        metrics: Metrics {
            requests_total: AtomicU64::new(0),
            start_epoch: now_unix(),
            backend,
            funnel: Funnel::default(),
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
/// The caller's IP for rate-limiting purposes.
///
/// Behind an L7 ingress every connection originates from the controller pod, so
/// `remote_addr()` is the SAME value for every user on the internet: one shared
/// bucket, and the per-IP limit becomes a global one that any single client can
/// exhaust for everyone. `X-Forwarded-For` carries the real client.
///
/// That header is attacker-controlled, so it is honoured ONLY when
/// `PROCTOR_SYNC_TRUST_PROXY` is set — a deployment fact the operator asserts,
/// not something inferred. A server exposed directly must not trust it, or
/// clients would forge a fresh identity per request and bypass limiting
/// entirely.
///
/// When trusted, the RIGHTMOST entry is taken. XFF reads
/// `client, proxy1, proxy2`; a client may prepend anything it likes, but the
/// last element is appended by the nearest trusted proxy and is the peer that
/// actually connected to it. Taking the leftmost would re-introduce the spoof.
fn client_ip(request: &Request) -> String {
    if std::env::var("PROCTOR_SYNC_TRUST_PROXY").is_ok_and(|v| v != "0" && !v.is_empty()) {
        let forwarded = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("X-Forwarded-For"))
            .and_then(|h| {
                h.value
                    .as_str()
                    .rsplit(',')
                    .map(str::trim)
                    .find(|s| !s.is_empty())
                    .map(str::to_string)
            });
        if let Some(ip) = forwarded {
            return ip;
        }
    }
    request
        .remote_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Hard ceiling on any request body the server will buffer, in bytes.
///
/// Every body was previously read with an unbounded `read_to_end` into a `Vec`,
/// so a single authenticated account could stream arbitrarily large payloads
/// into memory and then into Postgres (as TOASTed BYTEA on a 5 GiB volume).
/// The Traefik `buffering` middleware caps a single request at 16 MiB, but that
/// is an edge concern that self-hosters running the binary directly do not have
/// at all, and a per-request ceiling is not a budget — it does not stop a loop.
///
/// ADR-0004 listed "cap blob and SharedVault size" as an implemented DoS
/// mitigation. It was not implemented. This is that cap, at the application
/// layer where it belongs.
const MAX_BODY_BYTES: u64 = 16 * 1024 * 1024;

/// The recipient `member_id`s inside a serialized `SharedVault`, or `None` if the
/// blob is not in that shape.
///
/// Reads ONLY the ids. Those are public — the same server hands them out in the
/// membership directory — so no ciphertext, key or plaintext is inspected and
/// the zero-knowledge property is untouched. Deliberately parsed structurally
/// with `serde_json` rather than by depending on `proctor-passbook`, so the
/// server keeps no compile-time knowledge of the crypto types.
///
/// `None` (unrecognised shape) means the caller SKIPS the orphan check rather
/// than rejecting. Failing closed here would make the server the arbiter of a
/// client-side format it deliberately does not own, and would hard-break every
/// existing client the moment the envelope gains a field.
fn wrapped_member_ids(blob: &[u8]) -> Option<Vec<String>> {
    let v: serde_json::Value = serde_json::from_slice(blob).ok()?;
    let wrapped = v.get("wrapped")?.as_array()?;
    let ids: Vec<String> = wrapped
        .iter()
        .filter_map(|w| w.get("member_id")?.as_str().map(str::to_string))
        .collect();
    (ids.len() == wrapped.len()).then_some(ids)
}

/// Read a request body with a hard size limit. Returns `None` if the body
/// exceeds [`MAX_BODY_BYTES`] or cannot be read.
///
/// Reads `MAX_BODY_BYTES + 1` so that hitting the limit exactly is
/// distinguishable from exceeding it, rather than silently truncating — a
/// truncated blob would be stored as a valid-looking but corrupt vault.
fn read_body_limited(request: &mut Request) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let read = request
        .as_reader()
        .take(MAX_BODY_BYTES + 1)
        .read_to_end(&mut buf);
    match read {
        Ok(_) if buf.len() as u64 > MAX_BODY_BYTES => None,
        Ok(_) => Some(buf),
        Err(_) => None,
    }
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
        (Method::Post, "/v1/billing/checkout") => handle_billing_checkout(request, app),
        (Method::Post, "/v1/billing/webhook") => handle_billing_webhook(request, app),
        (_, path) if path == "/v1/groups" || path.starts_with("/v1/groups/") => {
            handle_groups(request, app, method, &url);
        }
        _ => respond(request, text("not found", 404)),
    }
}

/// Read a small JSON request body into a `Value`, tolerating an empty/absent body.
fn read_body_json(request: &mut Request) -> serde_json::Value {
    // Bounded like every other body read; an oversized JSON body yields Null,
    // which callers already treat as "absent/!invalid".
    let body = read_body_limited(request).unwrap_or_default();
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
            // Funnel entry point: everything downstream is measured against this.
            app.metrics
                .funnel
                .accounts_registered
                .fetch_add(1, Ordering::Relaxed);
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
                    // Paywall hit: measures how much real demand the free device cap blocks.
                    app.metrics
                        .funnel
                        .entitlement_denied_device_limit
                        .fetch_add(1, Ordering::Relaxed);
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
            let Some(blob) = read_body_limited(&mut request) else {
                respond(request, text("body too large", 413));
                return;
            };
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
#[derive(Clone, Copy, PartialEq, Eq)]
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
        ([id, "members", mid, "role"], Method::Post) => {
            handle_group_set_role(request, app, &account, id, mid)
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
        // Paywall hit: someone wanted to share and could not. The strongest
        // upgrade-intent signal we have.
        app.metrics
            .funnel
            .entitlement_denied_family_plan
            .fetch_add(1, Ordering::Relaxed);
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
        role: Role::Owner,
        added_epoch: now_unix(),
    };
    let group_id = groups::new_id();
    match app.groups.create(&group_id, owner) {
        Ok(_) => {
            app.metrics
                .funnel
                .groups_created
                .fetch_add(1, Ordering::Relaxed);
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

/// POST /v1/groups/{id}/invites — mint a single-use, TTL'd invite. Requires
/// **Admin or Owner** (inviting expands who can read the vault, so it is a
/// member-management action). Body: `{ttl_seconds?}`. Returns the plaintext
/// `invite_code` (shown once); the server keeps only its hash.
fn handle_group_invite(mut request: Request, app: &App, account: &str, id: &str) {
    // Authorization: Admin or Owner.
    match app.groups.get(id) {
        Ok(Some(g)) if g.can_manage_members(account) => {}
        Ok(Some(g)) if g.is_member(account) => {
            respond(request, text("admin or owner required to invite", 403));
            return;
        }
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
    // Invite lifetime: caller-supplied, defaulted to 24h, and CLAMPED to 24h.
    //
    // The clamp is the point. `ttl_seconds` was previously accepted unbounded
    // and fed straight into `now.saturating_add(ttl)`, so `u64::MAX` saturated
    // and `now_epoch >= invite.expires_epoch` could never fire — the invite
    // never expired. Combined with removal not invalidating invites, that was a
    // permanent readmission ticket: an Admin could mint one for themselves,
    // be removed, and redeem it later to regain access to the rotated vault.
    // Removal now invalidates pending invites and bars removed accounts, but an
    // unbounded TTL is indefensible on its own.
    const MAX_INVITE_TTL: u64 = 24 * 60 * 60;
    let ttl = read_body_json(&mut request)
        .get("ttl_seconds")
        .and_then(|v| v.as_u64())
        .filter(|&t| t > 0)
        .unwrap_or(MAX_INVITE_TTL)
        .min(MAX_INVITE_TTL);
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
            // Intent to share. The gap to `invites_redeemed` is the conversion we care about.
            app.metrics
                .funnel
                .invites_minted
                .fetch_add(1, Ordering::Relaxed);
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
        role: Role::Member,
        added_epoch: now_unix(),
    };
    match app
        .groups
        .redeem_invite(id, &groups::hash_code(&code), new_member, now_unix())
    {
        Ok(RedeemOutcome::Added) => {
            // The moment a family actually becomes more than one person.
            app.metrics
                .funnel
                .invites_redeemed
                .fetch_add(1, Ordering::Relaxed);
            eprintln!("POST /v1/groups/{id}/members -> 200 (account={account} joined)");
            respond(request, json(r#"{"joined":true}"#.to_string(), 200));
        }
        // Rejections are split by reason: expired points at our 24h TTL being too
        // short for how families really coordinate, invalid_or_used at the code
        // hand-off UX, no_such_group at a broken link or a deleted vault.
        //
        // The two below are not UX signals — they are policy refusals, and a
        // repeated count is worth looking at rather than designing around.
        Ok(RedeemOutcome::AccountRemoved) => {
            // A removed account tried to readmit itself with a stashed code.
            // Deliberately indistinguishable from invalid_or_used to the caller,
            // so probing cannot confirm removal state.
            eprintln!(
                "POST /v1/groups/{id}/members -> 403 (removed account={account} attempted rejoin)"
            );
            app.metrics
                .funnel
                .invites_rejected_invalid_or_used
                .fetch_add(1, Ordering::Relaxed);
            respond(request, text("invalid or already-used invite", 403))
        }
        Ok(RedeemOutcome::MemberIdTaken) => {
            // Client-chosen member_id colliding with another account's. Never
            // legitimate: ids are 128-bit random, so this is a client bug or an
            // attempt to hijack another member's wrapped-key slot.
            eprintln!(
                "POST /v1/groups/{id}/members -> 409 (member_id collision, account={account})"
            );
            respond(request, text("member id already in use", 409))
        }
        Ok(RedeemOutcome::Expired) => {
            app.metrics
                .funnel
                .invites_rejected_expired
                .fetch_add(1, Ordering::Relaxed);
            respond(request, text("invite expired", 403))
        }
        Ok(RedeemOutcome::InvalidOrUsed) => {
            app.metrics
                .funnel
                .invites_rejected_invalid_or_used
                .fetch_add(1, Ordering::Relaxed);
            respond(request, text("invalid or already-used invite", 403))
        }
        Ok(RedeemOutcome::NoSuchGroup) => {
            app.metrics
                .funnel
                .invites_rejected_no_such_group
                .fetch_add(1, Ordering::Relaxed);
            respond(request, text("no such group", 404))
        }
        Err(e) => respond_500(request, &e),
    }
}

/// DELETE /v1/groups/{id}/members/{mid} — remove a member. Requires **Admin or
/// Owner**, and an Owner can never be removed (protects the group from being
/// orphaned or captured). True revocation also requires the client to rotate the
/// vault key and re-push `/keys` + `/vault`; the server only drops the directory
/// entry.
fn handle_group_remove(request: Request, app: &App, account: &str, id: &str, member_id: &str) {
    match app.groups.get(id) {
        Ok(Some(g)) if g.can_manage_members(account) => {
            // Never remove an Owner, even as another Owner/Admin.
            if g.members
                .iter()
                .any(|m| m.member_id == member_id && m.role == Role::Owner)
            {
                respond(request, text("an owner cannot be removed", 403));
                return;
            }
        }
        Ok(Some(g)) if g.is_member(account) => {
            respond(request, text("admin or owner required", 403));
            return;
        }
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
    match app.groups.remove_member(id, member_id) {
        Ok(true) => {
            // Offboarding actually happening (and how often families need it).
            app.metrics
                .funnel
                .members_removed
                .fetch_add(1, Ordering::Relaxed);
            eprintln!("DELETE /v1/groups/{id}/members/{member_id} -> 200 (removed)");
            respond(request, json(r#"{"removed":true}"#.to_string(), 200));
        }
        Ok(false) => respond(request, text("no such member", 404)),
        Err(e) => respond_500(request, &e),
    }
}

/// POST /v1/groups/{id}/members/{mid}/role — change a member's role. **Owner
/// only**. Body: `{role: "member"|"admin"|"owner"}`. An Owner's role cannot be
/// changed (no demoting/capturing the owner), and an unrecognized role name fails
/// closed to `member` via [`Role::parse`].
fn handle_group_set_role(
    mut request: Request,
    app: &App,
    account: &str,
    id: &str,
    member_id: &str,
) {
    match app.groups.get(id) {
        Ok(Some(g)) if g.can_change_roles(account) => {
            if g.members
                .iter()
                .any(|m| m.member_id == member_id && m.role == Role::Owner)
            {
                respond(request, text("an owner's role cannot be changed", 403));
                return;
            }
        }
        Ok(Some(g)) if g.is_member(account) => {
            respond(request, text("owner only", 403));
            return;
        }
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
    let Some(role_name) = str_field(&read_body_json(&mut request), "role") else {
        respond(request, text("role required", 400));
        return;
    };
    let role = Role::parse(&role_name);
    match app.groups.set_member_role(id, member_id, role) {
        Ok(true) => {
            eprintln!(
                "POST /v1/groups/{id}/members/{member_id}/role -> 200 ({})",
                role.as_str()
            );
            respond(
                request,
                json(
                    serde_json::json!({ "role": role.as_str() }).to_string(),
                    200,
                ),
            );
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
            let Some(blob) = read_body_limited(&mut request) else {
                respond(request, text("body too large", 413));
                return;
            };
            // A keys blob must keep every CURRENT member reachable.
            //
            // Authorization here is membership, not role — and deliberately so:
            // the client's reconcile flow needs a plain Member to be able to
            // wrap the vault key to a new joiner (ADR-0004 specifies `(member)`),
            // so a role check would break onboarding. But that also meant the
            // lowest-privileged account — a child — could PUT a SharedVault
            // wrapping a fresh key to themselves alone. Every other member,
            // Owner included, then fails to unwrap; the client returns early
            // rather than repairing it; and blobs are overwritten in place with
            // no history. The family vault is destroyed for everyone.
            //
            // The right constraint is structural rather than role-based: a write
            // may not orphan an existing member. Dropping ids for people no
            // longer in the directory is exactly what rotation-on-revoke does,
            // so the rule is "must cover everyone still in the group", not
            // "must be strictly additive".
            //
            // Only `member_id`s are inspected. They are already public — they
            // are in the membership directory this same server serves — so this
            // reads no ciphertext and weakens the zero-knowledge property not at
            // all.
            if which == Blob::Keys {
                if let Some(new_ids) = wrapped_member_ids(&blob) {
                    let orphaned: Vec<&str> = group
                        .members
                        .iter()
                        .map(|m| m.member_id.as_str())
                        .filter(|id| !new_ids.iter().any(|n| n == id))
                        .collect();
                    if !orphaned.is_empty() {
                        eprintln!(
                            "PUT /v1/groups/{id}/keys -> 409 (account={account} would orphan {} member(s))",
                            orphaned.len()
                        );
                        respond(
                            request,
                            text("keys blob would lock out current members", 409),
                        );
                        return;
                    }
                }
            }

            let result = match which {
                Blob::Keys => app.groups.put_keys(id, expected, blob),
                Blob::Content => app.groups.put_content(id, expected, blob),
            };
            match result {
                Ok(version) => {
                    // A keys write means a member was really granted access (or a
                    // rotation landed); a content write means a shared item exists.
                    // Joining without either is a share that never delivered value.
                    match which {
                        Blob::Keys => &app.metrics.funnel.group_keys_writes,
                        Blob::Content => &app.metrics.funnel.group_content_writes,
                    }
                    .fetch_add(1, Ordering::Relaxed);
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

/// POST /v1/billing/checkout — auth. Create a Stripe subscription Checkout session
/// for the Family plan and return its hosted URL for the app to redirect to. The
/// account id rides in the session + subscription metadata so the webhook applies
/// the plan on completion. 503 if checkout is unconfigured; 502 on a Stripe error.
///
/// NOTE: this makes a **blocking** outbound HTTPS call and the server processes
/// requests sequentially, so a slow Stripe response briefly stalls other requests.
/// Checkout is infrequent; a threaded request model is a production follow-up.
fn handle_billing_checkout(request: Request, app: &App) {
    let account = match identity_for(&request, app) {
        Some(i) => i.account_id,
        None => {
            respond(request, text("unauthorized", 401));
            return;
        }
    };
    let Some(cfg) = &app.stripe_checkout else {
        respond(request, text("checkout not configured", 503));
        return;
    };
    let form = [
        ("mode", "subscription"),
        ("line_items[0][price]", cfg.price_family.as_str()),
        ("line_items[0][quantity]", "1"),
        ("success_url", cfg.success_url.as_str()),
        ("cancel_url", cfg.cancel_url.as_str()),
        ("client_reference_id", account.as_str()),
        ("metadata[account_id]", account.as_str()),
        ("subscription_data[metadata][account_id]", account.as_str()),
        ("subscription_data[metadata][plan]", "family"),
    ];
    let result = ureq::post("https://api.stripe.com/v1/checkout/sessions")
        .set("Authorization", &format!("Bearer {}", cfg.secret_key))
        .send_form(&form);
    match result {
        Ok(resp) => match resp
            .into_string()
            .ok()
            .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
        {
            Some(v) => match v.get("url").and_then(|u| u.as_str()) {
                Some(url) => {
                    eprintln!("POST /v1/billing/checkout -> 200 (session for account={account})");
                    respond(
                        request,
                        json(serde_json::json!({ "url": url }).to_string(), 200),
                    );
                }
                None => respond(request, text("stripe: no checkout url in response", 502)),
            },
            None => respond(request, text("stripe: unreadable response", 502)),
        },
        Err(e) => {
            eprintln!("stripe checkout error: {e}");
            respond(request, text("could not create checkout session", 502));
        }
    }
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

    /// A snapshot with distinct values per counter, so a mis-wired format argument
    /// (rendering the wrong field into the wrong metric) shows up as a wrong number.
    fn sample_snapshot() -> MetricsSnapshot<'static> {
        MetricsSnapshot {
            requests_total: 42,
            uptime_secs: 100,
            backend: "postgres",
            version: "1.33.0",
            funnel: FunnelSnapshot {
                accounts_registered: 1,
                groups_created: 2,
                invites_minted: 3,
                invites_redeemed: 4,
                invites_rejected_invalid_or_used: 5,
                invites_rejected_expired: 6,
                invites_rejected_no_such_group: 7,
                group_keys_writes: 8,
                group_content_writes: 9,
                members_removed: 10,
                entitlement_denied_device_limit: 11,
                entitlement_denied_family_plan: 12,
            },
        }
    }

    #[test]
    fn metrics_render_is_valid_prometheus() {
        let out = render_metrics(&sample_snapshot());
        assert!(out.contains("proctor_requests_total 42\n"));
        assert!(out.contains("proctor_uptime_seconds 100\n"));
        assert!(out.contains("proctor_build_info{backend=\"postgres\",version=\"1.33.0\"} 1\n"));
        // Every metric is preceded by its HELP/TYPE lines: 3 base + 9 funnel metrics
        // (the two labelled families each declare TYPE once, as Prometheus requires).
        assert_eq!(out.matches("# TYPE").count(), 12);
        assert_eq!(out.matches("# HELP").count(), 12);
    }

    #[test]
    fn funnel_counters_render_with_help_and_type() {
        let out = render_metrics(&sample_snapshot());
        for (name, value) in [
            ("proctor_accounts_registered_total", 1),
            ("proctor_groups_created_total", 2),
            ("proctor_invites_minted_total", 3),
            ("proctor_invites_redeemed_total", 4),
            ("proctor_group_keys_writes_total", 8),
            ("proctor_group_content_writes_total", 9),
            ("proctor_members_removed_total", 10),
        ] {
            assert!(
                out.contains(&format!("# HELP {name} ")),
                "missing HELP for {name}"
            );
            assert!(
                out.contains(&format!("# TYPE {name} counter\n")),
                "missing TYPE for {name}"
            );
            assert!(
                out.contains(&format!("{name} {value}\n")),
                "missing sample for {name}"
            );
        }
    }

    #[test]
    fn labelled_counters_render_every_reason() {
        let out = render_metrics(&sample_snapshot());
        // One HELP/TYPE per metric family, then one sample line per label value.
        assert_eq!(
            out.matches("# TYPE proctor_invites_rejected_total").count(),
            1
        );
        assert_eq!(
            out.matches("# TYPE proctor_entitlement_denied_total")
                .count(),
            1
        );
        assert!(out.contains("proctor_invites_rejected_total{reason=\"invalid_or_used\"} 5\n"));
        assert!(out.contains("proctor_invites_rejected_total{reason=\"expired\"} 6\n"));
        assert!(out.contains("proctor_invites_rejected_total{reason=\"no_such_group\"} 7\n"));
        assert!(out.contains("proctor_entitlement_denied_total{reason=\"device_limit\"} 11\n"));
        assert!(out.contains("proctor_entitlement_denied_total{reason=\"family_plan\"} 12\n"));
    }

    #[test]
    fn exposition_lines_are_well_formed_and_carry_no_identifiers() {
        let out = render_metrics(&sample_snapshot());
        for line in out.lines() {
            if line.starts_with('#') {
                continue;
            }
            // Every sample is `name[{labels}] <number>` — no free-form text.
            let (series, value) = line.rsplit_once(' ').expect("sample line has a value");
            assert!(
                value.parse::<u64>().is_ok(),
                "non-numeric sample value in {line:?}"
            );
            assert!(
                series.starts_with("proctor_"),
                "unexpected series {series:?}"
            );
            // Only these label keys exist anywhere in the exposition. `backend` and
            // `version` describe the deployment; `reason` is a fixed enum. Nothing is
            // derived from an account, group, member, device, or IP — a scrape can
            // never reconstruct the family graph.
            if let Some((_, labels)) = series.split_once('{') {
                for pair in labels.trim_end_matches('}').split(',') {
                    let key = pair.split_once('=').expect("key=value label").0;
                    assert!(
                        matches!(key, "backend" | "version" | "reason"),
                        "unexpected label key {key:?} — metrics must stay identifier-free"
                    );
                }
            }
        }
    }

    #[test]
    fn funnel_snapshot_reflects_increments() {
        let funnel = Funnel::default();
        assert_eq!(funnel.snapshot().invites_redeemed, 0);
        funnel.invites_redeemed.fetch_add(1, Ordering::Relaxed);
        funnel.invites_redeemed.fetch_add(1, Ordering::Relaxed);
        funnel.groups_created.fetch_add(1, Ordering::Relaxed);
        let snap = funnel.snapshot();
        assert_eq!(snap.invites_redeemed, 2);
        assert_eq!(snap.groups_created, 1);
        // Untouched counters stay at zero (no cross-wiring in `snapshot`).
        assert_eq!(snap.invites_minted, 0);
        assert_eq!(snap.entitlement_denied_family_plan, 0);
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

    #[test]
    fn wrapped_member_ids_reads_only_the_public_ids() {
        // The exact envelope the client PUTs: recipient id plus opaque crypto.
        let blob = br#"{"wrapped":[
            {"member_id":"m-a","ephemeral_public":[1],"nonce":[2],"ciphertext":[3]},
            {"member_id":"m-b","ephemeral_public":[4],"nonce":[5],"ciphertext":[6]}
        ]}"#;
        assert_eq!(
            wrapped_member_ids(blob),
            Some(vec!["m-a".to_string(), "m-b".to_string()])
        );
    }

    #[test]
    fn wrapped_member_ids_returns_none_for_unrecognised_shapes() {
        // None means "skip the orphan check", NOT "reject". The server does not
        // own this format, so an unfamiliar envelope must not brick clients.
        assert_eq!(wrapped_member_ids(b"not json"), None);
        assert_eq!(wrapped_member_ids(br#"{"other":[]}"#), None);
        // A member_id of the wrong type is a malformed entry, not an empty set:
        // returning Some(vec![]) here would let a caller orphan everyone.
        assert_eq!(
            wrapped_member_ids(br#"{"wrapped":[{"member_id":7}]}"#),
            None
        );
        // Empty recipient list IS well-formed, and correctly reports no ids --
        // which is exactly what the orphan check must catch.
        assert_eq!(wrapped_member_ids(br#"{"wrapped":[]}"#), Some(vec![]));
    }

    #[test]
    fn orphan_check_rejects_dropping_a_current_member_but_allows_revocation() {
        // Mirrors the handler's comparison. Directory: a, b.
        let dir = ["m-a", "m-b"];
        let orphans = |ids: Vec<&str>| -> usize {
            dir.iter().filter(|d| !ids.iter().any(|n| n == *d)).count()
        };
        // A Member wrapping only to themselves locks out everyone else.
        assert_eq!(orphans(vec!["m-a"]), 1);
        // Covering both current members is fine.
        assert_eq!(orphans(vec!["m-a", "m-b"]), 0);
        // Rotation may drop an id no longer in the directory -- that is exactly
        // what revoking m-c looks like -- so extra/absent non-members are fine.
        assert_eq!(orphans(vec!["m-a", "m-b", "m-z"]), 0);
    }
}
