//! Zero-knowledge sync server.
//!
//! A tiny HTTP API over [`proctor_sync`]. It stores an opaque sealed-vault blob
//! per account and never inspects it — no plaintext, master password, or Secret
//! Key ever reaches this process. Bearer tokens map to accounts; versioning is
//! optimistic (`If-Match`), so a stale push gets 409 and must pull first.
//!
//! Config (env):
//!   PROCTOR_SYNC_ADDR    listen address (default 127.0.0.1:8787)
//!   PROCTOR_SYNC_TOKENS  "token1:account1,token2:account2"
//!   PROCTOR_SYNC_DIR     storage dir (FileStore); unset → in-memory
//!
//! API:
//!   GET /v1/vault   -> 200 + blob (+ X-Vault-Version) | 404 | 401
//!   PUT /v1/vault   -> 200 + version (+ X-Vault-Version) | 409 (+ X-Vault-Version) | 401
//!   (If-Match: <version> on PUT; omit for the first upload.)

use proctor_sync::{FileStore, MemoryStore, SyncError, SyncStore};
use std::collections::HashMap;
use tiny_http::{Header, Method, Request, Response, Server};

fn main() {
    let addr = std::env::var("PROCTOR_SYNC_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
    let tokens = parse_tokens(&std::env::var("PROCTOR_SYNC_TOKENS").unwrap_or_default());

    let store: Box<dyn SyncStore + Send + Sync> = match std::env::var("PROCTOR_SYNC_DIR") {
        Ok(dir) if !dir.is_empty() => Box::new(FileStore::new(dir)),
        _ => Box::new(MemoryStore::new()),
    };

    let server = Server::http(&addr).unwrap_or_else(|e| {
        eprintln!("error: cannot bind {addr}: {e}");
        std::process::exit(1);
    });
    eprintln!(
        "proctor-sync-server listening on {addr} ({} account token(s))",
        tokens.len()
    );

    for request in server.incoming_requests() {
        handle(request, store.as_ref(), &tokens);
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

/// Resolve the account from a `Authorization: Bearer <token>` header.
fn account_for(request: &Request, tokens: &HashMap<String, String>) -> Option<String> {
    let auth = request.headers().iter().find(|h| {
        h.field
            .as_str()
            .as_str()
            .eq_ignore_ascii_case("authorization")
    })?;
    let token = auth.value.as_str().strip_prefix("Bearer ")?.trim();
    tokens.get(token).cloned()
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

fn handle(mut request: Request, store: &dyn SyncStore, tokens: &HashMap<String, String>) {
    let method = request.method().clone();
    let url = request.url().to_string();

    if url != "/v1/vault" {
        let _ = request.respond(Response::from_string("not found").with_status_code(404));
        return;
    }

    let account = match account_for(&request, tokens) {
        Some(a) => a,
        None => {
            eprintln!("{method} {url} -> 401 (bad/missing token)");
            let _ = request.respond(Response::from_string("unauthorized").with_status_code(401));
            return;
        }
    };

    match method {
        Method::Get => match store.get(&account) {
            Ok(Some(env)) => {
                eprintln!("GET {url} account={account} -> 200 v{}", env.version);
                let resp = Response::from_data(env.blob)
                    .with_status_code(200)
                    .with_header(version_header(env.version));
                let _ = request.respond(resp);
            }
            Ok(None) => {
                eprintln!("GET {url} account={account} -> 404 (no vault yet)");
                let _ = request.respond(Response::from_string("no vault").with_status_code(404));
            }
            Err(e) => respond_500(request, &e),
        },
        Method::Put => {
            let expected = if_match(&request);
            let mut blob = Vec::new();
            if request.as_reader().read_to_end(&mut blob).is_err() {
                let _ = request.respond(Response::from_string("bad body").with_status_code(400));
                return;
            }
            // NOTE: the blob is never logged or inspected — zero knowledge.
            match store.put(&account, expected, blob) {
                Ok(version) => {
                    eprintln!("PUT {url} account={account} -> 200 v{version}");
                    let resp = Response::from_string(version.to_string())
                        .with_status_code(200)
                        .with_header(version_header(version));
                    let _ = request.respond(resp);
                }
                Err(SyncError::Conflict { server_version }) => {
                    eprintln!("PUT {url} account={account} -> 409 (server v{server_version})");
                    let resp = Response::from_string("version conflict — pull first")
                        .with_status_code(409)
                        .with_header(version_header(server_version));
                    let _ = request.respond(resp);
                }
                Err(e) => respond_500(request, &e),
            }
        }
        _ => {
            let _ =
                request.respond(Response::from_string("method not allowed").with_status_code(405));
        }
    }
}

fn respond_500(request: Request, err: &SyncError) {
    eprintln!("error: {err}");
    let _ = request.respond(Response::from_string("server error").with_status_code(500));
}
