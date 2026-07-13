//! Zero-knowledge sync server.
//!
//! A tiny HTTP API over [`proctor_sync`]. It stores an opaque sealed-vault blob
//! per account and never inspects it — no plaintext, master password, or Secret
//! Key ever reaches this process. Per-device bearer tokens map to accounts via
//! the [`AccountStore`]; versioning is optimistic (`If-Match`), so a stale push
//! gets 409 and must pull first.
//!
//! Config (env):
//!   PROCTOR_SYNC_ADDR    listen address (default 127.0.0.1:8787)
//!   PROCTOR_SYNC_DIR     storage dir (FileStore + FileAccountStore); unset → in-memory
//!   PROCTOR_SYNC_TOKENS  optional pre-seed "token1:account1,token2:account2"
//!                        (the registry is the source of truth; this is a fallback
//!                        for tests/bootstrapping)
//!
//! API (every response, including errors, carries permissive CORS headers):
//!   POST /v1/register  -> 200 {account_id, device_token}                 (no auth)
//!   POST /v1/devices   -> 200 {device_token} (new token, same account)   | 401
//!   GET  /v1/vault     -> 200 + blob (+ X-Vault-Version) | 404 | 401
//!   PUT  /v1/vault     -> 200 + version (+ X-Vault-Version) | 409 (+ X-Vault-Version) | 401
//!   OPTIONS *          -> 204 (CORS preflight)
//!   (If-Match: <version> on PUT; omit for the first upload.)

use proctor_sync::{
    AccountStore, FileAccountStore, FileStore, MemoryAccountStore, MemoryStore, SyncError,
    SyncStore,
};
use std::collections::HashMap;
use std::io::{Cursor, Read};
use tiny_http::{Header, Method, Request, Response, Server};

/// Bundle of the two driven ports plus the optional static token pre-seed.
struct App {
    store: Box<dyn SyncStore + Send + Sync>,
    accounts: Box<dyn AccountStore + Send + Sync>,
    /// Optional pre-seeded token→account map. The registry is authoritative;
    /// this is only consulted as a fallback.
    seed_tokens: HashMap<String, String>,
}

fn main() {
    let addr = std::env::var("PROCTOR_SYNC_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
    let seed_tokens = parse_tokens(&std::env::var("PROCTOR_SYNC_TOKENS").unwrap_or_default());

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
    };

    let server = Server::http(&addr).unwrap_or_else(|e| {
        eprintln!("error: cannot bind {addr}: {e}");
        std::process::exit(1);
    });
    eprintln!(
        "proctor-sync-server listening on {addr} ({} pre-seeded token(s))",
        app.seed_tokens.len()
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
        h("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS"),
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

/// Resolve a request's bearer token to an account id. The registry is
/// authoritative; the static pre-seed map is a fallback for tests.
fn account_for(request: &Request, app: &App) -> Option<String> {
    let token = bearer_token(request)?;
    if let Ok(Some(account)) = app.accounts.account_for_token(&token) {
        return Some(account);
    }
    app.seed_tokens.get(&token).cloned()
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
        (Method::Post, "/v1/devices") => handle_add_device(request, app),
        (_, "/v1/vault") => handle_vault(request, app, method, &url),
        _ => respond(request, text("not found", 404)),
    }
}

/// POST /v1/register — no auth. Optional JSON body `{"email":"..."}`.
fn handle_register(mut request: Request, app: &App) {
    let mut body = Vec::new();
    if request.as_reader().read_to_end(&mut body).is_err() {
        respond(request, text("bad body", 400));
        return;
    }
    let email = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("email").and_then(|e| e.as_str()).map(str::to_string));

    match app.accounts.register(email.as_deref()) {
        Ok(account) => {
            eprintln!("POST /v1/register -> 200 account={}", account.account_id);
            let body = serde_json::json!({
                "account_id": account.account_id,
                "device_token": account.device_token,
            })
            .to_string();
            respond(request, json(body, 200));
        }
        Err(e) => respond_500(request, &e),
    }
}

/// POST /v1/devices — auth. Mints a second token for the SAME account.
fn handle_add_device(request: Request, app: &App) {
    let token = match bearer_token(&request) {
        Some(t) => t,
        None => {
            eprintln!("POST /v1/devices -> 401 (missing token)");
            respond(request, text("unauthorized", 401));
            return;
        }
    };
    match app.accounts.add_device(&token) {
        Ok(Some(new_token)) => {
            eprintln!("POST /v1/devices -> 200 (new device token issued)");
            let body = serde_json::json!({ "device_token": new_token }).to_string();
            respond(request, json(body, 200));
        }
        Ok(None) => {
            eprintln!("POST /v1/devices -> 401 (unknown token)");
            respond(request, text("unauthorized", 401));
        }
        Err(e) => respond_500(request, &e),
    }
}

/// GET/PUT /v1/vault — auth. Zero-knowledge blob get/put with optimistic
/// concurrency; the blob is never logged or inspected.
fn handle_vault(mut request: Request, app: &App, method: Method, url: &str) {
    let account = match account_for(&request, app) {
        Some(a) => a,
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

fn respond_500(request: Request, err: &SyncError) {
    eprintln!("error: {err}");
    respond(request, text("server error", 500));
}
