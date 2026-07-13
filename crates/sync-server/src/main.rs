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
//!   PROCTOR_SYNC_ADDR       listen address (default 127.0.0.1:8787)
//!   PROCTOR_SYNC_DIR        storage dir (FileStore + FileAccountStore); unset → in-memory
//!   PROCTOR_SYNC_TOKENS     optional pre-seed "token1:account1,token2:account2"
//!                           (the registry is the source of truth; this is a fallback
//!                           for tests/bootstrapping)
//!   PROCTOR_SYNC_TOKEN_TTL  optional device-token lifetime in seconds, applied on
//!                           register / add-device (unset or 0 → tokens never expire,
//!                           the backward-compatible default)
//!
//! API (every response, including errors, carries permissive CORS headers):
//!   POST   /v1/register       -> 200 {account_id, device_token, device_id}    (no auth)
//!   POST   /v1/devices        -> 200 {device_token, device_id} (same account) | 401
//!   POST   /v1/devices/rotate -> 200 {device_token, device_id} (same device)  | 401
//!   GET    /v1/devices        -> 200 {devices:[{id,label,created_epoch,expires_epoch,current}]} | 401
//!   DELETE /v1/devices/{id}   -> 200 {revoked:true} | 404 | 401  (revoke a device)
//!   GET    /v1/vault          -> 200 + blob (+ X-Vault-Version) | 404 | 401
//!   PUT    /v1/vault          -> 200 + version (+ X-Vault-Version) | 409 (+ X-Vault-Version) | 401
//!   DELETE /v1/vault          -> 204 | 401  (erase this account's vault, idempotent)
//!   OPTIONS *                 -> 204 (CORS preflight)
//!   (If-Match: <version> on PUT; omit for the first upload.)

use proctor_sync::{
    AccountStore, FileAccountStore, FileStore, MemoryAccountStore, MemoryStore, SyncError,
    SyncStore, TokenIdentity,
};
use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::time::{SystemTime, UNIX_EPOCH};
use tiny_http::{Header, Method, Request, Response, Server};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Bundle of the two driven ports plus the optional static token pre-seed.
struct App {
    store: Box<dyn SyncStore + Send + Sync>,
    accounts: Box<dyn AccountStore + Send + Sync>,
    /// Optional pre-seeded token→account map. The registry is authoritative;
    /// this is only consulted as a fallback.
    seed_tokens: HashMap<String, String>,
    /// Optional device-token lifetime (seconds) applied on register/add-device.
    /// `None` → tokens never expire (backward-compatible default).
    token_ttl: Option<u64>,
}

/// Read `PROCTOR_SYNC_TOKEN_TTL` as an optional lifetime in seconds. Unset,
/// unparseable, or `0` all mean "no expiry".
fn token_ttl_from_env() -> Option<u64> {
    std::env::var("PROCTOR_SYNC_TOKEN_TTL")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&ttl| ttl > 0)
}

fn main() {
    let addr = std::env::var("PROCTOR_SYNC_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
    let seed_tokens = parse_tokens(&std::env::var("PROCTOR_SYNC_TOKENS").unwrap_or_default());
    let token_ttl = token_ttl_from_env();

    let (store, accounts): (
        Box<dyn SyncStore + Send + Sync>,
        Box<dyn AccountStore + Send + Sync>,
    ) = match std::env::var("PROCTOR_SYNC_DIR") {
        Ok(dir) if !dir.is_empty() => (
            Box::new(FileStore::new(&dir)),
            Box::new(FileAccountStore::new(&dir)),
        ),
        _ => (
            Box::new(MemoryStore::new()),
            Box::new(MemoryAccountStore::new()),
        ),
    };

    let app = App {
        store,
        accounts,
        seed_tokens,
        token_ttl,
    };

    let server = Server::http(&addr).unwrap_or_else(|e| {
        eprintln!("error: cannot bind {addr}: {e}");
        std::process::exit(1);
    });
    eprintln!(
        "proctor-sync-server listening on {addr} ({} pre-seeded token(s), token ttl: {})",
        app.seed_tokens.len(),
        match app.token_ttl {
            Some(ttl) => format!("{ttl}s"),
            None => "none".to_string(),
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

    match (&method, url.as_str()) {
        (Method::Post, "/v1/register") => handle_register(request, app),
        (Method::Post, "/v1/devices/rotate") => handle_rotate_device(request, app),
        (Method::Post, "/v1/devices") => handle_add_device(request, app),
        (Method::Get, "/v1/devices") => handle_list_devices(request, app),
        (Method::Delete, path) if path.starts_with("/v1/devices/") => {
            let device_id = path.trim_start_matches("/v1/devices/").to_string();
            handle_revoke_device(request, app, &device_id);
        }
        (Method::Delete, "/v1/vault") => handle_delete_vault(request, app),
        (_, "/v1/vault") => handle_vault(request, app, method, &url),
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

fn respond_500(request: Request, err: &SyncError) {
    eprintln!("error: {err}");
    respond(request, text("server error", 500));
}
