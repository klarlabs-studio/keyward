//! Proctor Passbook CLI — manage a real on-disk consumer vault from the terminal.
//!
//! Config via env:
//!   PROCTOR_PASSBOOK             vault file path (default: ~/.proctor/passbook.json)
//!   PROCTOR_PASSBOOK_MASTER_FILE master password read from a file (preferred —
//!                                keeps it out of /proc/<pid>/environ)
//!   PROCTOR_PASSBOOK_MASTER      master password via env (fallback)
//!   PROCTOR_PASSBOOK_SECRETKEY_FILE  device Secret Key in Emergency-Kit format
//!                                (optional — enables 2SKD when present)
//!
//! Commands:
//!   passbook init
//!   passbook add-login <id> <title> <username> <password> [url] [totp_base32]
//!   passbook list [category]
//!   passbook show <id> [--reveal]
//!   passbook totp <id>
//!   passbook watchtower
//!   passbook emergency-kit

use proctor_passbook::{
    open, seal, totp, watchtower, Category, Content, Entry, Issue, Login, SealedVault, SecretKey,
};
use std::path::PathBuf;
use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};

mod bridge;

const TOTP_STEP: u64 = 30;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("");
    match cmd {
        "init" => cmd_init(),
        "add-login" => cmd_add_login(&args[1..]),
        "list" => cmd_list(&args[1..]),
        "show" => cmd_show(&args[1..]),
        "totp" => cmd_totp(&args[1..]),
        "watchtower" => cmd_watchtower(),
        "emergency-kit" => cmd_emergency_kit(),
        "bridge" => cmd_bridge(),
        "" => {
            eprintln!("{USAGE}");
            exit(2);
        }
        other => {
            eprintln!("unknown command: {other}\n{USAGE}");
            exit(2);
        }
    }
}

const USAGE: &str = "usage: passbook <command> [args]\n\
    \n\
    commands:\n\
    \x20 init                                             create an empty sealed vault (+ Secret Key)\n\
    \x20 add-login <id> <title> <user> <pass> [url] [totp]  add a login entry\n\
    \x20 list [category]                                  list entries (login|note|card|identity)\n\
    \x20 show <id> [--reveal]                             show an entry (password hidden unless --reveal)\n\
    \x20 totp <id>                                        current TOTP code + seconds remaining\n\
    \x20 watchtower                                       security report (weak / reused / no-2fa)\n\
    \x20 emergency-kit                                    print the Secret Key (Emergency-Kit format)\n\
    \x20 bridge                                           run the browser native-messaging host (stdio)";

// ---------------------------------------------------------------------------
// Config helpers (env + ~ expansion)
// ---------------------------------------------------------------------------

fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    if path == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home);
        }
    }
    PathBuf::from(path)
}

fn vault_path() -> PathBuf {
    match std::env::var("PROCTOR_PASSBOOK") {
        Ok(p) if !p.is_empty() => expand_home(&p),
        _ => expand_home("~/.proctor/passbook.json"),
    }
}

/// Read the master password from `PROCTOR_PASSBOOK_MASTER_FILE` (preferred) or
/// `PROCTOR_PASSBOOK_MASTER`. Exits(2) with a clear message if neither is set.
fn master() -> Vec<u8> {
    if let Ok(path) = std::env::var("PROCTOR_PASSBOOK_MASTER_FILE") {
        match std::fs::read_to_string(&path) {
            Ok(s) => return s.trim_end_matches(['\n', '\r']).as_bytes().to_vec(),
            Err(e) => {
                eprintln!("error: cannot read PROCTOR_PASSBOOK_MASTER_FILE {path}: {e}");
                exit(2);
            }
        }
    }
    match std::env::var("PROCTOR_PASSBOOK_MASTER") {
        Ok(m) if !m.is_empty() => {
            eprintln!(
                "note: PROCTOR_PASSBOOK_MASTER via env is readable via /proc; prefer PROCTOR_PASSBOOK_MASTER_FILE."
            );
            m.into_bytes()
        }
        _ => {
            eprintln!(
                "error: set PROCTOR_PASSBOOK_MASTER_FILE (preferred) or PROCTOR_PASSBOOK_MASTER."
            );
            exit(2);
        }
    }
}

fn secret_key_path() -> Option<PathBuf> {
    std::env::var("PROCTOR_PASSBOOK_SECRETKEY_FILE")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|s| expand_home(&s))
}

/// Load the Secret Key if a path is configured. Returns `None` when unset (the
/// vault is then master-only). Exits(2) on a configured-but-unreadable/invalid key.
fn load_secret_key() -> Option<SecretKey> {
    let path = secret_key_path()?;
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!(
            "error: cannot read PROCTOR_PASSBOOK_SECRETKEY_FILE {}: {e}",
            path.display()
        );
        exit(2);
    });
    match SecretKey::parse(&text) {
        Ok(sk) => Some(sk),
        Err(e) => {
            eprintln!("error: invalid Secret Key in {}: {e}", path.display());
            exit(2);
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Vault persistence
// ---------------------------------------------------------------------------

fn read_sealed(path: &PathBuf) -> SealedVault {
    if !path.exists() {
        eprintln!(
            "error: no vault at {} — run `passbook init` first.",
            path.display()
        );
        exit(1);
    }
    let bytes = std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("error: cannot read vault {}: {e}", path.display());
        exit(1);
    });
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        eprintln!("error: vault {} is corrupt: {e}", path.display());
        exit(1);
    })
}

fn write_sealed(path: &PathBuf, sealed: &SealedVault) {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).unwrap_or_else(|e| {
                eprintln!("error: cannot create {}: {e}", parent.display());
                exit(1);
            });
        }
    }
    let json = serde_json::to_vec_pretty(sealed).unwrap_or_else(|e| {
        eprintln!("error: cannot serialize vault: {e}");
        exit(1);
    });
    std::fs::write(path, json).unwrap_or_else(|e| {
        eprintln!("error: cannot write vault {}: {e}", path.display());
        exit(1);
    });
}

/// Open the on-disk vault into entries, mapping crypto failures to a clean message.
fn load_entries(path: &PathBuf, master: &[u8], sk: Option<&SecretKey>) -> Vec<Entry> {
    let sealed = read_sealed(path);
    open(&sealed, master, sk).unwrap_or_else(|e| {
        eprintln!("error: cannot open vault: {e}");
        exit(1);
    })
}

fn reseal(path: &PathBuf, entries: &[Entry], master: &[u8], sk: Option<&SecretKey>) {
    let sealed = seal(entries, master, sk).unwrap_or_else(|e| {
        eprintln!("error: cannot seal vault: {e}");
        exit(1);
    });
    write_sealed(path, &sealed);
}

fn category_label(c: Category) -> &'static str {
    match c {
        Category::Login => "login",
        Category::SecureNote => "note",
        Category::Card => "card",
        Category::Identity => "identity",
    }
}

fn match_category(filter: &str, c: Category) -> bool {
    matches!(
        (filter.to_lowercase().as_str(), c),
        ("login", Category::Login)
            | ("note", Category::SecureNote)
            | ("securenote", Category::SecureNote)
            | ("card", Category::Card)
            | ("identity", Category::Identity)
    )
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_init() {
    let path = vault_path();
    if path.exists() {
        eprintln!("error: vault already exists at {}", path.display());
        exit(1);
    }
    let m = master();

    // If a Secret Key path is configured but the file doesn't exist yet, generate
    // and persist one, then seal with 2SKD. Otherwise honor an existing key, or
    // fall back to master-only when no Secret Key path is set at all.
    let sk_path = secret_key_path();
    let secret_key: Option<SecretKey> = match &sk_path {
        Some(p) if p.exists() => load_secret_key(),
        Some(p) => {
            let sk = SecretKey::generate();
            if let Some(parent) = p.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).unwrap_or_else(|e| {
                        eprintln!("error: cannot create {}: {e}", parent.display());
                        exit(1);
                    });
                }
            }
            std::fs::write(p, sk.emergency_kit_format()).unwrap_or_else(|e| {
                eprintln!("error: cannot write Secret Key to {}: {e}", p.display());
                exit(1);
            });
            Some(sk)
        }
        None => None,
    };

    reseal(&path, &[], &m, secret_key.as_ref());
    println!("created empty vault at {}", path.display());

    // Emergency Kit — the user needs both their master password AND the Secret Key.
    if let Some(sk) = &secret_key {
        println!();
        println!("================= EMERGENCY KIT =================");
        println!("Keep this somewhere safe and offline. You need BOTH");
        println!("secrets to recover your vault:");
        println!();
        println!("  Master password : (the one you set — NOT stored here)");
        println!("  Secret Key      : {}", sk.emergency_kit_format());
        if let Some(p) = &sk_path {
            println!();
            println!("  Secret Key saved to: {}", p.display());
        }
        println!("================================================");
    } else {
        println!("note: no PROCTOR_PASSBOOK_SECRETKEY_FILE set — vault is master-only (no 2SKD).");
    }
}

fn cmd_add_login(rest: &[String]) {
    if rest.len() < 4 {
        eprintln!(
            "usage: passbook add-login <id> <title> <username> <password> [url] [totp_base32]"
        );
        exit(2);
    }
    let (id, title, username, password) = (&rest[0], &rest[1], &rest[2], &rest[3]);
    let url = rest.get(4).filter(|s| !s.is_empty());
    let totp_secret = rest.get(5).filter(|s| !s.is_empty()).cloned();

    let path = vault_path();
    let m = master();
    let sk = load_secret_key();
    let mut entries = load_entries(&path, &m, sk.as_ref());

    if entries.iter().any(|e| &e.id == id) {
        eprintln!("error: entry '{id}' already exists");
        exit(1);
    }

    let login = Login {
        username: username.clone(),
        password: password.clone(),
        urls: url.map(|u| vec![u.clone()]).unwrap_or_default(),
        totp_secret,
        has_passkey: false,
    };
    entries.push(Entry {
        id: id.clone(),
        title: title.clone(),
        tags: Vec::new(),
        favorite: false,
        updated_epoch: now_unix(),
        content: Content::Login(login),
    });

    reseal(&path, &entries, &m, sk.as_ref());
    println!("added login '{id}' ({} entries total)", entries.len());
}

fn cmd_list(rest: &[String]) {
    let filter = rest.first();
    let path = vault_path();
    let entries = load_entries(&path, &master(), load_secret_key().as_ref());

    let rows: Vec<&Entry> = entries
        .iter()
        .filter(|e| {
            filter
                .map(|f| match_category(f, e.category()))
                .unwrap_or(true)
        })
        .collect();

    if rows.is_empty() {
        if let Some(f) = filter {
            println!("(no entries in category '{f}')");
        } else {
            println!("(vault is empty)");
        }
        return;
    }

    println!("{:<16} {:<24} {:<10} USERNAME", "ID", "TITLE", "CATEGORY");
    for e in rows {
        let username = match &e.content {
            Content::Login(l) => l.username.as_str(),
            Content::Identity(i) => i.email.as_str(),
            _ => "-",
        };
        println!(
            "{:<16} {:<24} {:<10} {}",
            e.id,
            e.title,
            category_label(e.category()),
            username
        );
    }
}

fn cmd_show(rest: &[String]) {
    let reveal = rest.iter().any(|a| a == "--reveal");
    let id = match rest.iter().find(|a| !a.starts_with("--")) {
        Some(id) => id,
        None => {
            eprintln!("usage: passbook show <id> [--reveal]");
            exit(2);
        }
    };

    let path = vault_path();
    let entries = load_entries(&path, &master(), load_secret_key().as_ref());
    let entry = entries.iter().find(|e| &e.id == id).unwrap_or_else(|| {
        eprintln!("error: no entry with id '{id}'");
        exit(1);
    });

    println!("id       : {}", entry.id);
    println!("title    : {}", entry.title);
    println!("category : {}", category_label(entry.category()));
    if !entry.tags.is_empty() {
        println!("tags     : {}", entry.tags.join(", "));
    }
    println!("favorite : {}", entry.favorite);

    match &entry.content {
        Content::Login(l) => {
            println!("username : {}", l.username);
            if reveal {
                println!("password : {}", l.password);
            } else {
                println!("password : •••••••• (pass --reveal to show)");
            }
            if !l.urls.is_empty() {
                println!("urls     : {}", l.urls.join(", "));
            }
            println!(
                "totp     : {}",
                if l.totp_secret.is_some() {
                    "configured (use `passbook totp`)"
                } else {
                    "none"
                }
            );
            println!("passkey  : {}", l.has_passkey);
        }
        Content::SecureNote(note) => {
            if reveal {
                println!("note     : {note}");
            } else {
                println!("note     : •••••••• (pass --reveal to show)");
            }
        }
        Content::Card(c) => {
            println!("cardholder : {}", c.cardholder);
            if reveal {
                println!("number     : {}", c.number);
                println!("cvv        : {}", c.cvv);
            } else {
                println!("number     : •••• •••• •••• •••• (pass --reveal to show)");
                println!("cvv        : ••• (pass --reveal to show)");
            }
            println!("expiry     : {}", c.expiry);
        }
        Content::Identity(i) => {
            println!("full name : {}", i.full_name);
            println!("email     : {}", i.email);
            println!("phone     : {}", i.phone);
            println!("address   : {}", i.address);
        }
    }
}

fn cmd_totp(rest: &[String]) {
    let id = match rest.first() {
        Some(id) => id,
        None => {
            eprintln!("usage: passbook totp <id>");
            exit(2);
        }
    };
    let path = vault_path();
    let entries = load_entries(&path, &master(), load_secret_key().as_ref());
    let entry = entries.iter().find(|e| &e.id == id).unwrap_or_else(|| {
        eprintln!("error: no entry with id '{id}'");
        exit(1);
    });
    let secret = match &entry.content {
        Content::Login(l) => l.totp_secret.as_deref(),
        _ => None,
    };
    let secret = secret.unwrap_or_else(|| {
        eprintln!("error: entry '{id}' has no TOTP secret configured");
        exit(1);
    });
    let now = now_unix();
    match totp::code_now(secret, now) {
        Some(code) => {
            let remaining = totp::seconds_remaining(now, TOTP_STEP);
            println!("{code}  ({remaining}s remaining)");
        }
        None => {
            eprintln!("error: could not compute TOTP — is the secret valid base32?");
            exit(1);
        }
    }
}

fn cmd_watchtower() {
    let path = vault_path();
    let entries = load_entries(&path, &master(), load_secret_key().as_ref());
    let issues = watchtower(&entries);

    let login_count = entries
        .iter()
        .filter(|e| matches!(e.content, Content::Login(_)))
        .count();

    println!("== Watchtower security report ==");
    println!();

    if issues.is_empty() {
        println!("No issues found across {login_count} login(s). ✓");
    } else {
        for issue in &issues {
            match issue {
                Issue::Weak(id, bits) => {
                    println!("WEAK     {id}  (~{bits} bits — below 60-bit threshold)");
                }
                Issue::Reused(ids) => {
                    println!("REUSED   {} share the same password", ids.join(", "));
                }
                Issue::Missing2fa(id) => {
                    println!("NO-2FA   {id}  (2FA available but no TOTP stored)");
                }
            }
        }
    }

    // Simple score: start at 100, subtract per finding, floor at 0.
    let penalty: u32 = issues
        .iter()
        .map(|i| match i {
            Issue::Weak(_, _) => 15,
            Issue::Reused(ids) => 10 * ids.len() as u32,
            Issue::Missing2fa(_) => 5,
        })
        .sum();
    let score = 100u32.saturating_sub(penalty);
    println!();
    println!(
        "Security score: {score}/100  ({} issue(s), {login_count} login(s))",
        issues.len()
    );
}

/// Run the Chrome native-messaging host: load the vault once, then serve the
/// browser extension over stdio until it closes the pipe.
fn cmd_bridge() {
    let path = vault_path();
    let entries = load_entries(&path, &master(), load_secret_key().as_ref());
    if let Err(e) = bridge::run(&entries) {
        eprintln!("error: native-messaging bridge failed: {e}");
        exit(1);
    }
}

fn cmd_emergency_kit() {
    match load_secret_key() {
        Some(sk) => {
            println!("Secret Key: {}", sk.emergency_kit_format());
        }
        None => {
            eprintln!(
                "error: no Secret Key configured — set PROCTOR_PASSBOOK_SECRETKEY_FILE (this vault may be master-only)."
            );
            exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_home_replaces_tilde() {
        std::env::set_var("HOME", "/home/tester");
        assert_eq!(
            expand_home("~/.proctor/x.json"),
            PathBuf::from("/home/tester/.proctor/x.json")
        );
        assert_eq!(expand_home("/abs/path"), PathBuf::from("/abs/path"));
    }

    #[test]
    fn category_labels_are_stable() {
        assert_eq!(category_label(Category::Login), "login");
        assert_eq!(category_label(Category::SecureNote), "note");
        assert_eq!(category_label(Category::Card), "card");
        assert_eq!(category_label(Category::Identity), "identity");
    }

    #[test]
    fn category_filter_matches_aliases() {
        assert!(match_category("login", Category::Login));
        assert!(match_category("note", Category::SecureNote));
        assert!(match_category("securenote", Category::SecureNote));
        assert!(match_category("CARD", Category::Card));
        assert!(!match_category("login", Category::Card));
    }

    /// Smoke test: seal an empty vault to disk, add a login, reopen, and confirm
    /// the round-trip works end-to-end through the same persistence helpers the
    /// CLI uses.
    #[test]
    fn seal_add_reopen_roundtrip() {
        let dir = std::env::temp_dir().join(format!("passbook-cli-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.json");
        let master = b"correct horse battery staple";

        reseal(&path, &[], master, None);
        let mut entries = load_entries(&path, master, None);
        assert!(entries.is_empty());

        entries.push(Entry::login(
            "e1",
            "GitHub",
            "octo",
            "S7r0ng!Pass#word_2026",
        ));
        reseal(&path, &entries, master, None);

        let reopened = load_entries(&path, master, None);
        assert_eq!(reopened.len(), 1);
        assert_eq!(reopened[0].id, "e1");
        assert_eq!(reopened[0].title, "GitHub");

        // The persisted file is a JSON SealedVault, not plaintext entries.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("ciphertext"));
        assert!(!raw.contains("S7r0ng"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
