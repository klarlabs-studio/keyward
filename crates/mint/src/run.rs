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

/// OS-level isolation for the spawned process. Env injection is hygiene, not a
/// boundary (`/proc/<pid>/environ` is readable by same-UID processes); real
/// isolation comes from running the command in a namespace or container so its
/// `/proc` and filesystem don't cross to the host. See ADR-0002.
#[derive(Debug, Clone)]
pub enum Isolation {
    /// No isolation (same-UID local process). Fine for trusted interactive use;
    /// NOT safe for untrusted-content-driven autonomy.
    None,
    /// Linux user/pid/mount namespaces via bubblewrap (`bwrap`); remounts /proc.
    Bubblewrap,
    /// A container runtime (`docker`/`podman`): separate /proc + filesystem, torn
    /// down after (`--rm`). The credential is passed with `--env NAME` (value from
    /// the runtime's own env), never in argv.
    Container { runtime: String, image: String, network: String },
}

/// The concrete command to spawn after applying an isolation strategy.
#[derive(Debug, Clone)]
pub struct Plan {
    pub program: String,
    pub args: Vec<String>,
    /// Env to set on the spawned (outer) process. Never placed in argv.
    pub env: BTreeMap<String, String>,
}

impl Isolation {
    /// A short label for logs/responses (e.g. "none", "bwrap", "docker:alpine").
    pub fn label(&self) -> String {
        match self {
            Isolation::None => "none".into(),
            Isolation::Bubblewrap => "bwrap".into(),
            Isolation::Container { runtime, image, .. } => format!("{runtime}:{image}"),
        }
    }

    /// Wrap `program args` (with `env`) into the command that actually runs.
    /// The credential (in `env`) is never placed into argv by any backend.
    pub fn wrap(&self, program: &str, args: &[String], env: &BTreeMap<String, String>) -> Plan {
        match self {
            Isolation::None => Plan {
                program: program.to_string(),
                args: args.to_vec(),
                env: env.clone(),
            },
            Isolation::Bubblewrap => {
                let mut a: Vec<String> = vec![
                    "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
                    "--proc", "/proc", "--dev", "/dev", "--ro-bind", "/", "/", "--",
                ]
                .into_iter()
                .map(String::from)
                .collect();
                a.push(program.to_string());
                a.extend(args.iter().cloned());
                Plan { program: "bwrap".into(), args: a, env: env.clone() }
            }
            Isolation::Container { runtime, image, network } => {
                let mut a: Vec<String> =
                    vec!["run".into(), "--rm".into(), "--network".into(), network.clone()];
                // `--env NAME` (name only) → value taken from the runtime's env,
                // so the secret never appears in argv (/proc/cmdline is public).
                for k in env.keys() {
                    a.push("--env".into());
                    a.push(k.clone());
                }
                a.push(image.clone());
                a.push(program.to_string());
                a.extend(args.iter().cloned());
                Plan { program: runtime.clone(), args: a, env: env.clone() }
            }
        }
    }
}

/// Run under an isolation strategy: wrap, then execute the resulting plan.
pub fn run_isolated(
    iso: &Isolation,
    program: &str,
    args: &[String],
    env: &BTreeMap<String, String>,
) -> std::io::Result<RunResult> {
    let plan = iso.wrap(program, args, env);
    run_with_env(&plan.program, &plan.args, &plan.env)
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

    fn secret_env() -> BTreeMap<String, String> {
        let mut e = BTreeMap::new();
        e.insert("DEMO_TOKEN".to_string(), "supersecret".to_string());
        e
    }

    #[test]
    fn none_isolation_is_passthrough() {
        let plan = Isolation::None.wrap("echo", &["hi".into()], &secret_env());
        assert_eq!(plan.program, "echo");
        assert_eq!(plan.args, vec!["hi"]);
    }

    #[test]
    fn container_keeps_secret_out_of_argv() {
        let iso = Isolation::Container {
            runtime: "docker".into(),
            image: "alpine".into(),
            network: "bridge".into(),
        };
        let plan = iso.wrap("aws", &["s3".into(), "ls".into()], &secret_env());
        assert_eq!(plan.program, "docker");
        let argv = plan.args.join(" ");
        assert!(argv.contains("run --rm --network bridge"));
        assert!(argv.contains("--env DEMO_TOKEN"));
        assert!(argv.contains("alpine aws s3 ls"));
        // The invariant: the secret VALUE never appears in argv (/proc/cmdline is public).
        assert!(!argv.contains("supersecret"), "secret leaked into argv: {argv}");
        // But it is set on the runtime process's env so --env NAME picks it up.
        assert_eq!(plan.env.get("DEMO_TOKEN").unwrap(), "supersecret");
    }

    #[test]
    fn bubblewrap_remounts_proc_and_keeps_secret_out_of_argv() {
        let plan = Isolation::Bubblewrap.wrap("aws", &["s3".into()], &secret_env());
        assert_eq!(plan.program, "bwrap");
        let argv = plan.args.join(" ");
        assert!(argv.contains("--proc /proc"));
        assert!(argv.contains("-- aws s3"));
        assert!(!argv.contains("supersecret"));
    }

    #[test]
    fn run_isolated_none_executes() {
        let r = run_isolated(&Isolation::None, "echo", &["hi".into()], &BTreeMap::new()).unwrap();
        assert_eq!(r.stdout.trim(), "hi");
    }
}
