//! Generic subprocess execution with credential injected via the environment —
//! the `op run` / vault-agent pattern. One runner covers every CLI-driven
//! provider (aws, terraform, hcloud, gcloud, kubectl…); the per-provider part is
//! a declarative profile (see `proctor-profiles`), not code here.
//!
//! SECURITY (see ADR-0002): env injection is *hygiene, not an isolation
//! boundary* — the value is readable via `/proc/<pid>/environ`, `ps`, and by any
//! same-UID process, and inherited by children. Never put secrets in argv
//! (`/proc/<pid>/cmdline` is world-readable) — this runner injects via env only.
//! For untrusted-content-driven autonomy, run under OS-level isolation
//! (PID/mount namespace or a container backend) and prefer short-TTL creds.

use std::collections::BTreeMap;
use std::process::Command;

/// Max bytes of captured output returned (per stream).
const MAX_OUTPUT: usize = 8_000;

#[derive(Debug, Clone)]
pub struct RunResult {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}

fn cap(bytes: &[u8]) -> (String, bool) {
    let s = String::from_utf8_lossy(bytes);
    if s.len() > MAX_OUTPUT {
        // char-safe truncation
        (s.chars().take(MAX_OUTPUT).collect(), true)
    } else {
        (s.into_owned(), false)
    }
}

/// Run `program args...` with `env` injected. The credential is passed *only* via
/// the environment — never argv. Captures stdout/stderr; waits for exit.
pub fn run_with_env(
    program: &str,
    args: &[String],
    env: &BTreeMap<String, String>,
) -> std::io::Result<RunResult> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output()?;
    let (stdout, t1) = cap(&out.stdout);
    let (stderr, t2) = cap(&out.stderr);
    Ok(RunResult {
        code: out.status.code(),
        stdout,
        stderr,
        truncated: t1 || t2,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_and_captures_stdout() {
        let r = run_with_env("echo", &["hello".into()], &BTreeMap::new()).unwrap();
        assert_eq!(r.stdout.trim(), "hello");
        assert_eq!(r.code, Some(0));
    }

    #[test]
    fn injects_env_without_putting_secret_in_argv() {
        let mut env = BTreeMap::new();
        env.insert("SECRET_TOK".to_string(), "supersecret".to_string());
        // Prove the var reached the process, without echoing its value.
        let r = run_with_env(
            "sh",
            &["-c".into(), "test -n \"$SECRET_TOK\" && echo present".into()],
            &env,
        )
        .unwrap();
        assert_eq!(r.stdout.trim(), "present");
        assert!(!r.stdout.contains("supersecret"));
    }

    #[test]
    fn nonzero_exit_is_captured() {
        let r = run_with_env("sh", &["-c".into(), "exit 3".into()], &BTreeMap::new()).unwrap();
        assert_eq!(r.code, Some(3));
    }
}
