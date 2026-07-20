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
    mut r: impl Read,
    mut w: impl Write,
    entries: &[Entry],
    version: &str,
    now: impl Fn() -> u64,
) -> io::Result<()> {
    while let Some(frame) = read_frame(&mut r)? {
        let reply = match serde_json::from_slice::<Value>(&frame) {
            Ok(req) => handle_request(&req, entries, now(), version),
            Err(e) => json!({ "error": format!("invalid json: {e}") }),
        };
        let bytes = serde_json::to_vec(&reply).unwrap_or_else(|_| b"{}".to_vec());
        write_frame(&mut w, &bytes)?;
    }
    Ok(())
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
}
