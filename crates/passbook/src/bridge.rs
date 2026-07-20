//! The autofill bridge protocol, shared by every host that answers it.
//!
//! Chrome's native-messaging wire format: each message is a little-endian `u32`
//! length followed by that many bytes of UTF-8 JSON.
//!
//! Requests (extension → host):
//!   {"type":"ping"}                       -> {"ok":true,"version":"…"}
//!   {"type":"list","origin":"github.com"} -> {"items":[{id,title,username,url,hasTotp}]}
//!   {"type":"get","id":"e1"}              -> {"id,username,password,totp}
//!
//! The `list` reply carries NO secrets — only enough to render the picker.
//! Passwords and TOTP codes cross the pipe only in a `get` reply, at fill time.
//!
//! WHY THIS LIVES IN THE LIBRARY, NOT THE CLI. There are now two hosts that must
//! speak this exact protocol: the `passbook` CLI (the prototype bridge that reads
//! a master-password file) and, per issue #13, the Keyward DESKTOP APP, which
//! will answer from an unlocked session unlocked via biometrics — the 1Password
//! model, without a plaintext master file. Both call `serve`; neither reimplements
//! the wire format or the request handling, so the two hosts can never drift on
//! what the extension sees. `handle_request` is pure (no I/O) and exhaustively
//! tested; `serve` is the thin transport loop over any reader/writer.

use crate::{totp, Content, Entry};
use serde_json::{json, Value};
use std::io::{self, Read, Write};
use zeroize::Zeroize;

/// Matches Chrome's 1 MiB per-message cap; a larger frame is a protocol error.
pub const MAX_MSG: u32 = 1024 * 1024;

/// Extract the bare host from a stored URL or an origin string:
/// scheme, credentials, port, path and a trailing dot are all stripped.
fn host_of(url: &str) -> String {
    let s = url.trim();
    // `split("://")` over a &str pattern is not a DoubleEndedIterator, so take the
    // last segment with `.last()` (the host part, whether or not a scheme was present).
    let s = s.split("://").last().unwrap_or(s);
    let s = s.split('/').next().unwrap_or(s);
    let s = s.split('?').next().unwrap_or(s);
    let s = s.rsplit('@').next().unwrap_or(s);
    let s = s.split(':').next().unwrap_or(s);
    s.trim_end_matches('.').to_ascii_lowercase()
}

/// True if a login stored for `stored_url` should offer to fill on `page_host`
/// — exact host match, or `page_host` is a subdomain of the stored host.
fn origin_matches(stored_url: &str, page_host: &str) -> bool {
    let stored = host_of(stored_url);
    if stored.is_empty() || page_host.is_empty() {
        return false;
    }
    page_host == stored || page_host.ends_with(&format!(".{stored}"))
}

/// Handle one parsed request against the in-memory entries. Pure: no I/O, so it
/// is exhaustively unit-tested. `now` is the unix time for TOTP computation, and
/// `version` is the reporting host's version (each caller passes its own — a CLI
/// bridge and the desktop app are distinct hosts with distinct versions).
pub fn handle_request(req: &Value, entries: &[Entry], now: u64, version: &str) -> Value {
    match req.get("type").and_then(Value::as_str) {
        Some("ping") => json!({ "ok": true, "version": version }),

        Some("list") => {
            let host = host_of(req.get("origin").and_then(Value::as_str).unwrap_or(""));
            let items: Vec<Value> = entries
                .iter()
                .filter_map(|e| match &e.content {
                    Content::Login(l) if l.urls.iter().any(|u| origin_matches(u, &host)) => {
                        Some(json!({
                            "id": e.id,
                            "title": e.title,
                            "username": l.username,
                            "url": l.urls.first().cloned().unwrap_or_default(),
                            "hasTotp": l.totp_secret.is_some(),
                        }))
                    }
                    _ => None,
                })
                .collect();
            json!({ "items": items })
        }

        Some("get") => {
            let id = req.get("id").and_then(Value::as_str).unwrap_or("");
            match entries.iter().find(|e| e.id == id) {
                Some(e) => match &e.content {
                    Content::Login(l) => {
                        let code = l
                            .totp_secret
                            .as_deref()
                            .and_then(|s| totp::code_now(s, now));
                        json!({
                            "id": e.id,
                            "username": l.username,
                            "password": l.password,
                            "totp": code,
                        })
                    }
                    _ => json!({ "error": "not a login" }),
                },
                None => json!({ "error": "not found" }),
            }
        }

        _ => json!({ "error": "unknown request" }),
    }
}

/// A held autofill session — the desktop agent's view of the vault (ADR-0007).
///
/// The CLI host answers from a fixed `&[Entry]` and is always "unlocked". The
/// desktop agent is different: the decrypted vault lives in the WebView, so the
/// frontend *feeds* the agent its logins at unlock (`unlock`) and clears them at
/// lock (`lock`). Between those, the plaintext logins are held here, in the
/// running app's memory — the "held session" ADR-0007 §3 describes.
///
/// Locked is the default and the safe state: a live agent socket that is bound
/// but locked answers `ping` (so the extension can prompt for unlock) but hands
/// out nothing — `list` is empty and `get` is refused. This is why binding the
/// socket at startup, before any unlock, is inert rather than a leak.
pub struct Session {
    entries: Vec<Entry>,
    locked: bool,
}

/// Locked, holding nothing — the only safe default for a bag of plaintext logins.
/// A derived `Default` would give `locked: false` (bool's default), i.e. an *open*
/// empty vault, which is exactly the footgun a password manager must not have.
impl Default for Session {
    fn default() -> Self {
        Session::locked()
    }
}

impl Session {
    /// A locked session holding no secrets — the startup state.
    pub fn locked() -> Self {
        Session {
            entries: Vec::new(),
            locked: true,
        }
    }

    /// An unlocked session serving `entries`.
    pub fn unlocked(entries: Vec<Entry>) -> Self {
        Session {
            entries,
            locked: false,
        }
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Replace the held logins and mark the session unlocked. Any previously held
    /// secrets are wiped first, so re-unlocking never leaves an old password
    /// lingering in the freed capacity.
    pub fn unlock(&mut self, entries: Vec<Entry>) {
        self.wipe();
        self.entries = entries;
        self.locked = false;
    }

    /// Drop and best-effort-zeroize the held secrets, returning to the locked
    /// state. Called when the user locks the vault or the app shuts down.
    pub fn lock(&mut self) {
        self.wipe();
        self.locked = true;
    }

    /// Zeroize the plaintext passwords and TOTP seeds before the backing `String`s
    /// are freed. Best-effort — it cannot cover copies the allocator or the OS may
    /// have made, a limit ADR-0007 documents — but it removes the standing copy
    /// this process controls.
    fn wipe(&mut self) {
        for e in &mut self.entries {
            if let Content::Login(l) = &mut e.content {
                l.password.zeroize();
                if let Some(secret) = &mut l.totp_secret {
                    secret.zeroize();
                }
            }
        }
        self.entries.clear();
    }
}

/// Handle one request against a held `Session` — the desktop agent's entry point,
/// wrapping the shared `handle_request` with ADR-0007 §3's locked-by-default rule.
///
/// Locked: `ping` still answers (advertising `locked:true` so the extension can
/// offer an unlock), `list` returns no items, and `get` is refused. Unlocked: it
/// delegates to the same `handle_request` the CLI host uses — so the two hosts
/// cannot drift — and annotates `ping` with `locked:false`.
pub fn handle_request_for(req: &Value, session: &Session, now: u64, version: &str) -> Value {
    let ty = req.get("type").and_then(Value::as_str);
    if session.locked {
        return match ty {
            Some("ping") => json!({ "ok": true, "version": version, "locked": true }),
            Some("list") => json!({ "items": [], "locked": true }),
            Some("get") => json!({ "error": "locked" }),
            _ => json!({ "error": "unknown request" }),
        };
    }
    let mut reply = handle_request(req, &session.entries, now, version);
    if ty == Some("ping") {
        reply["locked"] = json!(false);
    }
    reply
}

/// Read one native-messaging frame. `Ok(None)` on a clean EOF at a frame boundary.
pub fn read_frame(r: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf);
    if len == 0 || len > MAX_MSG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame length out of range",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

/// Write one native-messaging frame (length prefix + payload) and flush.
pub fn write_frame(w: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "reply too large"))?;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

/// Serve native-messaging requests over `r`/`w` until the peer closes the pipe.
/// Transport-agnostic: the CLI passes locked stdio; the desktop host (issue #13)
/// will pass whatever channel Chrome hands its native-messaging process. `now`
/// is injected so tests are deterministic and the caller owns the clock.
pub fn serve(
    r: impl Read,
    w: impl Write,
    entries: &[Entry],
    version: &str,
    now: impl Fn() -> u64,
) -> io::Result<()> {
    serve_frames(r, w, |req| handle_request(req, entries, now(), version))
}

/// The transport loop, parameterized over how each request is answered. Both the
/// CLI host (`serve`, over a fixed entry set) and the desktop agent (over a held,
/// lockable `Session`) drive it, so the framing and error handling exist once and
/// the two hosts cannot diverge on it. `respond` is called once per frame with
/// the parsed request; the loop owns the wire format, it owns the answer.
fn serve_frames(
    mut r: impl Read,
    mut w: impl Write,
    respond: impl Fn(&Value) -> Value,
) -> io::Result<()> {
    while let Some(frame) = read_frame(&mut r)? {
        let reply = match serde_json::from_slice::<Value>(&frame) {
            Ok(req) => respond(&req),
            Err(e) => json!({ "error": format!("invalid json: {e}") }),
        };
        let bytes = serde_json::to_vec(&reply).unwrap_or_else(|_| b"{}".to_vec());
        write_frame(&mut w, &bytes)?;
    }
    Ok(())
}

/// The local IPC that separates the process Chrome launches from the process
/// holding the unlocked vault — see ADR-0007. Chrome launches a short-lived
/// **connector**; the unlocked session lives in a long-running **agent** (the
/// desktop app). They speak the same framed protocol over a user-private Unix
/// socket, so `serve` above is reused verbatim on the agent side and this module
/// adds only the socket plumbing.
///
/// Unix-only for now (macOS/Linux). Windows uses a named pipe; that is a later
/// slice and deliberately not stubbed here rather than faked.
#[cfg(unix)]
pub mod ipc {
    use super::{handle_request_for, read_frame, serve, serve_frames, write_frame, Entry, Session};
    use std::io::{self, Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::{fs, thread};

    /// Wall-clock seconds, the unit TOTP wants. Its own fn so the agent loop
    /// reads clearly and the closure passed to `serve` stays trivial.
    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Answer one already-accepted connection with the bridge protocol. Split out
    /// from `run_agent` so it can be tested over a `UnixStream::pair()` with no
    /// filesystem socket.
    pub fn serve_connection(
        stream: UnixStream,
        entries: &[Entry],
        version: &str,
    ) -> io::Result<()> {
        // `serve` needs an independent reader and writer; a socket is full-duplex,
        // so a cloned handle to the same fd gives both without buffering surprises.
        let reader = stream.try_clone()?;
        serve(reader, stream, entries, version, now_unix)
    }

    /// Agent: accept connections on `listener` and serve each. One connection per
    /// Chrome native-messaging session, matching how the connector holds the
    /// socket open for the life of that session. Serial by design — a single
    /// desktop user is not driving concurrent autofill, and serial keeps the
    /// held-session access trivially free of data races. Caller owns socket
    /// permissions (ADR-0007: a 0700 dir) before binding.
    pub fn run_agent(listener: &UnixListener, entries: &[Entry], version: &str) -> io::Result<()> {
        for conn in listener.incoming() {
            // One misbehaving connection must not kill the agent for the next.
            if let Err(e) = serve_connection(conn?, entries, version) {
                eprintln!("keyward agent: connection ended with error: {e}");
            }
        }
        Ok(())
    }

    /// Connector: the dumb relay Chrome launches. Pumps each framed request from
    /// Chrome (`chrome_in`) to the agent socket and each framed reply back to
    /// Chrome (`chrome_out`). Holds no secrets and never parses the JSON — it
    /// only moves length-prefixed frames, so a protocol change needs no connector
    /// change. Returns when either side hits a clean EOF at a frame boundary.
    pub fn run_connector(
        agent_socket: &UnixStream,
        mut chrome_in: impl Read,
        mut chrome_out: impl Write,
    ) -> io::Result<()> {
        let mut to_agent = agent_socket.try_clone()?;
        let mut from_agent = agent_socket.try_clone()?;
        while let Some(frame) = read_frame(&mut chrome_in)? {
            write_frame(&mut to_agent, &frame)?;
            match read_frame(&mut from_agent)? {
                Some(reply) => write_frame(&mut chrome_out, &reply)?,
                // Agent closed mid-exchange: stop rather than spin.
                None => break,
            }
        }
        Ok(())
    }

    /// Answer one connection from a **held, lockable** `Session` (the desktop app),
    /// rather than a fixed entry set (the CLI host's `serve_connection`). The
    /// session is read under its lock **once per request**, not once per
    /// connection — so if the user locks the vault while Chrome holds the
    /// native-messaging pipe open, the very next `get` on that same pipe is
    /// refused. Locked-by-default (ADR-0007 §3) lives entirely in
    /// `handle_request_for`; this function only supplies the current session.
    pub fn serve_connection_session(
        stream: UnixStream,
        session: &Mutex<Session>,
        version: &str,
    ) -> io::Result<()> {
        let reader = stream.try_clone()?;
        serve_frames(reader, stream, |req| {
            // A poisoned lock still holds a valid Session; recover it rather than
            // panic the agent thread and take the bridge down.
            let held = session.lock().unwrap_or_else(|e| e.into_inner());
            handle_request_for(req, &held, now_unix(), version)
        })
    }

    /// Agent: accept connections on `listener` and serve each from the shared
    /// `session`. Serial by design, like `run_agent` — one desktop user is not
    /// driving concurrent autofill, and serial keeps the held-session access free
    /// of data races beyond the `Mutex` itself. Runs until the listener errors;
    /// the caller typically spawns it on its own thread (`spawn_agent`).
    pub fn run_agent_session(
        listener: &UnixListener,
        session: Arc<Mutex<Session>>,
        version: &str,
    ) -> io::Result<()> {
        for conn in listener.incoming() {
            // One misbehaving connection must not kill the agent for the next.
            if let Err(e) = serve_connection_session(conn?, &session, version) {
                eprintln!("keyward agent: connection ended with error: {e}");
            }
        }
        Ok(())
    }

    /// Ensure a user-private `0700` directory for the agent socket under
    /// `runtime_dir` and return the socket path inside it. ADR-0007 §1: the `0700`
    /// directory borrows the kernel's same-user isolation — another user on the
    /// box cannot even traverse into it, so cross-user access is denied for free.
    /// `runtime_dir` is the caller's choice (`$XDG_RUNTIME_DIR` on Linux, the
    /// per-user temp dir on macOS), kept out of the library so it stays portable.
    pub fn agent_socket_path(runtime_dir: &Path) -> io::Result<PathBuf> {
        let dir = runtime_dir.join("keyward");
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        Ok(dir.join("agent.sock"))
    }

    /// Bind the agent listener at `path`, clearing any stale socket a previous run
    /// left behind (which would otherwise fail the bind with `EADDRINUSE`), and
    /// tighten the socket node itself to `0600`.
    pub fn bind_agent_socket(path: &Path) -> io::Result<UnixListener> {
        let _ = fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(listener)
    }

    /// Bind the agent socket under `runtime_dir` and run its accept loop on a
    /// background thread, serving from `session`. Returns the bound socket path so
    /// the caller can advertise it to the connector and unlink it on shutdown. The
    /// one call a host needs: the desktop app invokes this once at startup with a
    /// freshly-`locked` session, then flips the session to unlocked on user
    /// unlock — no secret has to exist for the socket to come up.
    pub fn spawn_agent(
        runtime_dir: &Path,
        session: Arc<Mutex<Session>>,
        version: &'static str,
    ) -> io::Result<PathBuf> {
        let path = agent_socket_path(runtime_dir)?;
        let listener = bind_agent_socket(&path)?;
        thread::spawn(move || {
            if let Err(e) = run_agent_session(&listener, session, version) {
                eprintln!("keyward agent: listener stopped: {e}");
            }
        });
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Entry;
    use std::io::Cursor;

    fn sample() -> Vec<Entry> {
        let mut gh = Entry::login("e1", "GitHub", "octo", "s3cr3t!pw");
        if let Content::Login(l) = &mut gh.content {
            l.urls = vec!["https://github.com".into()];
            l.totp_secret = Some("JBSWY3DPEHPK3PXP".into());
        }
        let mut nf = Entry::login("e2", "Netflix", "fam", "flixpass");
        if let Content::Login(l) = &mut nf.content {
            l.urls = vec!["netflix.com".into()];
        }
        vec![gh, nf]
    }

    #[test]
    fn host_of_normalizes() {
        assert_eq!(host_of("https://github.com/login?x=1"), "github.com");
        assert_eq!(host_of("user@GitHub.com:443"), "github.com");
        assert_eq!(host_of("netflix.com"), "netflix.com");
    }

    #[test]
    fn origin_matches_host_and_subdomain() {
        assert!(origin_matches("https://github.com", "github.com"));
        assert!(origin_matches("github.com", "gist.github.com"));
        assert!(!origin_matches("github.com", "notgithub.com"));
        assert!(!origin_matches("github.com", "evil.com"));
    }

    #[test]
    fn list_matches_origin_and_hides_secrets() {
        let req = json!({ "type": "list", "origin": "https://github.com/login" });
        let resp = handle_request(&req, &sample(), 0, "test");
        let items = resp["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], "e1");
        assert_eq!(items[0]["hasTotp"], true);
        // The list must never carry a password.
        assert!(items[0].get("password").is_none());
    }

    #[test]
    fn list_empty_for_unrelated_site() {
        let req = json!({ "type": "list", "origin": "https://example.com" });
        let resp = handle_request(&req, &sample(), 0, "test");
        assert!(resp["items"].as_array().unwrap().is_empty());
    }

    #[test]
    fn get_returns_secret_and_totp_code() {
        let req = json!({ "type": "get", "id": "e1" });
        let resp = handle_request(&req, &sample(), 1_700_000_000, "test");
        assert_eq!(resp["password"], "s3cr3t!pw");
        // A TOTP secret is configured, so a 6-digit code comes back.
        let code = resp["totp"].as_str().unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn get_missing_is_an_error_not_a_panic() {
        let resp = handle_request(
            &json!({ "type": "get", "id": "nope" }),
            &sample(),
            0,
            "test",
        );
        assert_eq!(resp["error"], "not found");
    }

    #[test]
    fn ping_reports_the_callers_version() {
        // The version is the CALLER's, not baked in — so the CLI and the desktop
        // app each report their own.
        let resp = handle_request(&json!({ "type": "ping" }), &sample(), 0, "9.9.9");
        assert_eq!(resp["ok"], true);
        assert_eq!(resp["version"], "9.9.9");
    }

    #[test]
    fn unknown_request_is_rejected() {
        let resp = handle_request(&json!({ "type": "wat" }), &sample(), 0, "test");
        assert_eq!(resp["error"], "unknown request");
    }

    #[test]
    fn unlocked_session_answers_like_the_shared_handler() {
        let session = Session::unlocked(sample());
        let resp = handle_request_for(
            &json!({ "type": "get", "id": "e1" }),
            &session,
            1_700_000_000,
            "test",
        );
        assert_eq!(resp["password"], "s3cr3t!pw");
        // ping is annotated so the extension knows the agent is unlocked.
        let ping = handle_request_for(&json!({ "type": "ping" }), &session, 0, "2.1.0");
        assert_eq!(ping["ok"], true);
        assert_eq!(ping["locked"], false);
    }

    #[test]
    fn locked_session_refuses_get_and_empties_list() {
        let session = Session::locked();
        // get: no secret crosses a locked session.
        let get = handle_request_for(&json!({ "type": "get", "id": "e1" }), &session, 0, "test");
        assert_eq!(get["error"], "locked");
        // list: nothing, but flagged locked so the extension can offer an unlock.
        let list = handle_request_for(
            &json!({ "type": "list", "origin": "https://github.com" }),
            &session,
            0,
            "test",
        );
        assert!(list["items"].as_array().unwrap().is_empty());
        assert_eq!(list["locked"], true);
        // ping still answers while locked — that is how the extension learns to prompt.
        let ping = handle_request_for(&json!({ "type": "ping" }), &session, 0, "2.1.0");
        assert_eq!(ping["ok"], true);
        assert_eq!(ping["locked"], true);
        assert_eq!(ping["version"], "2.1.0");
    }

    #[test]
    fn locking_a_session_refuses_afterwards_and_unlocking_restores() {
        let mut session = Session::unlocked(sample());
        assert!(!session.is_locked());
        assert_eq!(session.len(), 2);

        session.lock();
        assert!(session.is_locked());
        assert!(session.is_empty());
        let after_lock =
            handle_request_for(&json!({ "type": "get", "id": "e1" }), &session, 0, "test");
        assert_eq!(after_lock["error"], "locked");

        session.unlock(sample());
        assert!(!session.is_locked());
        let after_unlock = handle_request_for(
            &json!({ "type": "get", "id": "e1" }),
            &session,
            1_700_000_000,
            "test",
        );
        assert_eq!(after_unlock["password"], "s3cr3t!pw");
    }

    #[test]
    fn a_default_session_is_locked() {
        // The desktop agent binds its socket from a default session at startup,
        // before any unlock; that default must be locked, not an open vault.
        assert!(Session::default().is_locked());
    }

    #[test]
    fn frames_round_trip() {
        let payload = br#"{"type":"ping"}"#;
        let mut buf = Vec::new();
        write_frame(&mut buf, payload).unwrap();
        // 4-byte little-endian length prefix.
        assert_eq!(&buf[..4], &(payload.len() as u32).to_le_bytes());

        let mut cur = Cursor::new(buf);
        let got = read_frame(&mut cur).unwrap().unwrap();
        assert_eq!(got, payload);
        // Clean EOF at the next boundary.
        assert!(read_frame(&mut cur).unwrap().is_none());
    }

    #[test]
    fn oversized_frame_is_rejected() {
        let mut bad = Vec::new();
        bad.extend_from_slice(&(MAX_MSG + 1).to_le_bytes());
        let mut cur = Cursor::new(bad);
        assert!(read_frame(&mut cur).is_err());
    }

    #[test]
    fn serve_answers_a_framed_request_end_to_end() {
        // A full ping through the transport loop: framed in, framed out. This is
        // the path both hosts share; a regression here breaks the extension for
        // CLI and desktop at once.
        let mut input = Vec::new();
        write_frame(&mut input, br#"{"type":"ping"}"#).unwrap();
        let mut output = Vec::new();
        serve(Cursor::new(input), &mut output, &sample(), "2.1.0", || 0).unwrap();

        let mut cur = Cursor::new(output);
        let reply = read_frame(&mut cur).unwrap().unwrap();
        let v: Value = serde_json::from_slice(&reply).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["version"], "2.1.0");
    }

    #[cfg(unix)]
    mod ipc_tests {
        use super::super::ipc;
        use super::super::{read_frame, write_frame};
        use super::sample;
        use serde_json::Value;
        use std::io::Cursor;
        use std::os::unix::net::{UnixListener, UnixStream};
        use std::thread;

        /// The agent, run over a socket pair (no filesystem), answers the protocol
        /// from a held entry set — the desktop-app side of ADR-0007's relay.
        #[test]
        fn agent_answers_get_over_a_socket_with_the_real_secret() {
            let (client, server) = UnixStream::pair().unwrap();
            let agent = thread::spawn(move || {
                ipc::serve_connection(server, &sample(), "2.1.0").unwrap();
            });

            let mut c = client;
            write_frame(&mut c, br#"{"type":"get","id":"e1"}"#).unwrap();
            let reply = read_frame(&mut c).unwrap().unwrap();
            let v: Value = serde_json::from_slice(&reply).unwrap();
            assert_eq!(v["password"], "s3cr3t!pw");
            let code = v["totp"].as_str().unwrap();
            assert_eq!(code.len(), 6);

            drop(c); // EOF → serve_connection returns → thread joins
            agent.join().unwrap();
        }

        /// The FULL relay: fake-Chrome frames → connector → agent socket → back.
        /// Proves the two-process shape works, not just `serve` in isolation.
        #[test]
        fn connector_relays_chrome_frames_to_the_agent_and_back() {
            let (agent_side, connector_side) = UnixStream::pair().unwrap();
            let agent = thread::spawn(move || {
                ipc::serve_connection(agent_side, &sample(), "2.1.0").unwrap();
            });

            // Fake Chrome: one framed ping in, capture the framed reply out.
            let mut chrome_in = Vec::new();
            write_frame(&mut chrome_in, br#"{"type":"ping"}"#).unwrap();
            let mut chrome_out = Vec::new();
            ipc::run_connector(&connector_side, Cursor::new(chrome_in), &mut chrome_out).unwrap();

            let mut cur = Cursor::new(chrome_out);
            let reply = read_frame(&mut cur).unwrap().unwrap();
            let v: Value = serde_json::from_slice(&reply).unwrap();
            assert_eq!(v["ok"], true);
            assert_eq!(v["version"], "2.1.0");

            drop(connector_side);
            agent.join().unwrap();
        }

        /// The desktop agent serves from a HELD, shared session over a socket —
        /// the desktop side of ADR-0007, distinct from the CLI's fixed entry set.
        #[test]
        fn agent_session_answers_get_from_a_held_unlocked_session() {
            use super::super::Session;
            use std::sync::{Arc, Mutex};

            let session = Arc::new(Mutex::new(Session::unlocked(sample())));
            let (client, server) = UnixStream::pair().unwrap();
            let held = Arc::clone(&session);
            let agent = thread::spawn(move || {
                ipc::serve_connection_session(server, &held, "2.1.0").unwrap();
            });

            let mut c = client;
            write_frame(&mut c, br#"{"type":"get","id":"e1"}"#).unwrap();
            let reply = read_frame(&mut c).unwrap().unwrap();
            let v: Value = serde_json::from_slice(&reply).unwrap();
            assert_eq!(v["password"], "s3cr3t!pw");

            drop(c);
            agent.join().unwrap();
        }

        /// Locking the vault mid-connection refuses the NEXT `get` on the same
        /// open pipe — proving the session is read per-request, not snapshotted
        /// once when Chrome connected. This is the property that makes "lock the
        /// vault" actually stop autofill immediately (ADR-0007 §3).
        #[test]
        fn locking_mid_connection_refuses_the_next_get() {
            use super::super::Session;
            use std::sync::{Arc, Mutex};

            let session = Arc::new(Mutex::new(Session::unlocked(sample())));
            let (client, server) = UnixStream::pair().unwrap();
            let held = Arc::clone(&session);
            let agent = thread::spawn(move || {
                ipc::serve_connection_session(server, &held, "2.1.0").unwrap();
            });

            let mut c = client;
            // First get, while unlocked: the real secret comes back.
            write_frame(&mut c, br#"{"type":"get","id":"e1"}"#).unwrap();
            let first = read_frame(&mut c).unwrap().unwrap();
            let v: Value = serde_json::from_slice(&first).unwrap();
            assert_eq!(v["password"], "s3cr3t!pw");

            // The user locks the vault while Chrome still holds the pipe open.
            session.lock().unwrap().lock();

            // Same connection, next get: refused, no secret.
            write_frame(&mut c, br#"{"type":"get","id":"e1"}"#).unwrap();
            let second = read_frame(&mut c).unwrap().unwrap();
            let v: Value = serde_json::from_slice(&second).unwrap();
            assert_eq!(v["error"], "locked");
            assert!(v.get("password").is_none());

            drop(c);
            agent.join().unwrap();
        }

        /// The socket helpers put the socket in a `0700` directory and the socket
        /// node at `0600` — ADR-0007 §1's same-user isolation, asserted on the
        /// real filesystem bits rather than assumed.
        #[test]
        fn agent_socket_lands_in_a_0700_dir_with_a_0600_node() {
            use std::os::unix::fs::PermissionsExt;

            let base = std::env::temp_dir().join(format!("kw-sock-perms-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(&base).unwrap();

            let path = ipc::agent_socket_path(&base).unwrap();
            let dir_mode = std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);

            let listener = ipc::bind_agent_socket(&path).unwrap();
            let node_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(node_mode, 0o600);

            drop(listener);
            let _ = std::fs::remove_dir_all(&base);
        }

        /// The agent bound to a REAL filesystem socket (as it runs in production),
        /// answering a client that connects by path. Covers `run_agent`'s accept
        /// loop, which the socket-pair tests bypass.
        #[test]
        fn agent_serves_over_a_real_bound_socket() {
            let dir = std::env::temp_dir().join(format!("kw-agent-test-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("agent.sock");
            let _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path).unwrap();

            let entries = sample();
            let agent = thread::spawn(move || {
                // Serve exactly one connection, then stop (test-scoped).
                let conn = listener.incoming().next().unwrap().unwrap();
                ipc::serve_connection(conn, &entries, "2.1.0").unwrap();
            });

            let mut client = UnixStream::connect(&path).unwrap();
            write_frame(
                &mut client,
                br#"{"type":"list","origin":"https://github.com/login"}"#,
            )
            .unwrap();
            let reply = read_frame(&mut client).unwrap().unwrap();
            let v: Value = serde_json::from_slice(&reply).unwrap();
            assert_eq!(v["items"].as_array().unwrap().len(), 1);
            // The list still carries no password across the socket.
            assert!(v["items"][0].get("password").is_none());

            drop(client);
            agent.join().unwrap();
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_dir(&dir);
        }
    }
}
