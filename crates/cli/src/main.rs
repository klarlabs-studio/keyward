//! Proctor CLI — manage a real on-disk vault and demonstrate the broker.
//!
//! Config via env:
//!   PROCTOR_VAULT   path to the vault file (default: ./proctor-vault.json)
//!   PROCTOR_MASTER  master secret used to seal/open the vault (required for
//!                   init/add/list). In production this is master-password +
//!                   device Secret Key; here a passphrase stands in.
//!
//! Commands:
//!   proctor init
//!   proctor add <id> <label> <origins-csv> <secret> [mintable:true|false=false] [kind]
//!   proctor list
//!   proctor profiles (list loaded provider profiles from $PROCTOR_PROFILES)
//!   proctor demo     (in-memory broker walkthrough)

use proctor_broker::{Action, ActionVerb, Broker, Denied, Grant, ItemRef, Mode, Policy};
use proctor_vault::{load_from_file, save_to_file, Item, ItemKind};
use std::path::PathBuf;
use std::process::exit;
use std::time::SystemTime;

fn vault_path() -> PathBuf {
    std::env::var("PROCTOR_VAULT")
        .unwrap_or_else(|_| "proctor-vault.json".to_string())
        .into()
}

fn master() -> Vec<u8> {
    // Prefer a file (PROCTOR_MASTER_FILE) so the master isn't exposed via /proc.
    if let Ok(path) = std::env::var("PROCTOR_MASTER_FILE") {
        match std::fs::read_to_string(&path) {
            Ok(s) => return s.trim_end_matches(['\n', '\r']).as_bytes().to_vec(),
            Err(e) => {
                eprintln!("error: cannot read PROCTOR_MASTER_FILE {path}: {e}");
                exit(2);
            }
        }
    }
    match std::env::var("PROCTOR_MASTER") {
        Ok(m) if !m.is_empty() => {
            eprintln!("note: PROCTOR_MASTER via env is readable via /proc; prefer PROCTOR_MASTER_FILE.");
            m.into_bytes()
        }
        _ => {
            eprintln!("error: set PROCTOR_MASTER_FILE (preferred) or PROCTOR_MASTER.");
            exit(2);
        }
    }
}

fn parse_kind(s: &str) -> ItemKind {
    match s.to_lowercase().as_str() {
        "password" => ItemKind::Password,
        "apikey" | "api_key" | "token" => ItemKind::ApiKey,
        "totp" | "totpseed" => ItemKind::TotpSeed,
        _ => ItemKind::Note,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("demo");
    match cmd {
        "init" => cmd_init(),
        "add" => cmd_add(&args[1..]),
        "list" => cmd_list(),
        "profiles" => cmd_profiles(),
        "demo" => demo(),
        other => {
            eprintln!("unknown command: {other}\nusage: proctor <init|add|list|profiles|demo>");
            exit(2);
        }
    }
}

fn profiles_dir() -> PathBuf {
    if let Ok(p) = std::env::var("PROCTOR_PROFILES") {
        return p.into();
    }
    match std::env::var("HOME") {
        Ok(home) => PathBuf::from(home).join(".proctor/profiles"),
        Err(_) => PathBuf::from("profiles"),
    }
}

fn cmd_profiles() {
    let dir = profiles_dir();
    let reg = proctor_profiles::Registry::load_dir(&dir).unwrap_or_else(|e| {
        eprintln!("failed to load profiles from {}: {e}", dir.display());
        exit(1);
    });
    if reg.is_empty() {
        println!("no profiles in {} — drop <id>.toml files there to add providers", dir.display());
        return;
    }
    println!("{} profile(s) from {}\n", reg.len(), dir.display());
    println!("{:<12} {:<10} {}", "ID", "INJECT", "DESCRIPTION");
    for p in reg.iter() {
        let inject = if p.env_var.is_some() { "env_var" } else { "env_map" };
        println!("{:<12} {:<10} {}", p.id, inject, p.description);
    }
}

fn cmd_init() {
    let path = vault_path();
    if path.exists() {
        eprintln!("vault already exists at {}", path.display());
        exit(1);
    }
    save_to_file(&path, &[], &master()).unwrap_or_else(|e| {
        eprintln!("failed to create vault: {e}");
        exit(1);
    });
    println!("created empty vault at {}", path.display());
}

fn cmd_add(rest: &[String]) {
    if rest.len() < 4 {
        eprintln!("usage: proctor add <id> <label> <origins-csv> <secret> [mintable:true|false=false] [kind] [provider]");
        eprintln!("  mintable defaults to false — Proctor stores and uses the token directly (no minting).");
        eprintln!("  provider links the item to a profile (e.g. aws, github) for run_command.");
        exit(2);
    }
    let (id, label, origins_csv, secret) = (&rest[0], &rest[1], &rest[2], &rest[3]);
    let mintable = rest
        .get(4)
        .map(|m| matches!(m.to_lowercase().as_str(), "true" | "yes" | "1"))
        .unwrap_or(false);
    let kind = rest.get(5).map(|s| parse_kind(s)).unwrap_or(ItemKind::Password);
    let provider = rest.get(6).map(|s| s.to_string());
    let origins: Vec<String> = origins_csv
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    let path = vault_path();
    let m = master();
    let mut items = load_from_file(&path, &m).unwrap_or_else(|e| {
        eprintln!("failed to open vault at {}: {e}", path.display());
        exit(1);
    });
    if items.iter().any(|i| &i.id == id) {
        eprintln!("item '{id}' already exists");
        exit(1);
    }
    items.push(Item::new(id.clone(), label.clone(), kind, origins, mintable, secret.clone()).with_provider(provider));
    save_to_file(&path, &items, &m).unwrap_or_else(|e| {
        eprintln!("failed to save vault: {e}");
        exit(1);
    });
    println!("added item '{id}' ({} items total)", items.len());
}

fn cmd_list() {
    let path = vault_path();
    let items = load_from_file(&path, &master()).unwrap_or_else(|e| {
        eprintln!("failed to open vault at {}: {e}", path.display());
        exit(1);
    });
    if items.is_empty() {
        println!("(vault is empty)");
        return;
    }
    println!("{:<16} {:<20} {:<8} {}", "ID", "LABEL", "MINTABLE", "ORIGINS");
    for i in &items {
        println!(
            "{:<16} {:<20} {:<8} {}",
            i.id,
            i.label,
            i.mintable,
            i.bound_origins.join(",")
        );
    }
}

fn demo() {
    println!("== Proctor broker demo ==\n");

    let github = ItemRef {
        id: "itm_github".into(),
        label: "GitHub".into(),
        bound_origins: vec!["github.com".into()],
        mintable: true,
    };
    let bank = ItemRef {
        id: "itm_bank".into(),
        label: "Bank".into(),
        bound_origins: vec!["bank.com".into()],
        mintable: false,
    };

    let mut broker = Broker::new(Policy::with_approved_origins(&["github.com", "bank.com"]));
    let now = SystemTime::now();

    let scenarios: Vec<(&str, &ItemRef, Action, Mode, bool)> = vec![
        ("agent reads GitHub (bound, reversible, unattended)", &github, Action::new(ActionVerb::Read, "github.com"), Mode::Unattended, false),
        ("INJECTED: use GitHub creds on evil.example.com", &github, Action::new(ActionVerb::Read, "evil.example.com"), Mode::Unattended, false),
        ("agent wants to ship to prod, unattended", &github, Action::new(ActionVerb::ShipToProduction, "github.com"), Mode::Unattended, false),
        ("agent wants to move money, unattended", &bank, Action::new(ActionVerb::MoveMoney, "bank.com"), Mode::Unattended, false),
        ("agent wants to move money, human present", &bank, Action::new(ActionVerb::MoveMoney, "bank.com"), Mode::Attended, false),
        ("agent demands the raw GitHub secret", &github, Action::new(ActionVerb::Read, "github.com"), Mode::Attended, true),
    ];

    for (desc, item, action, mode, raw) in scenarios {
        let verb = action.verb.as_str();
        let outcome = match broker.request_use(item, &action, mode, raw, now) {
            Ok(Grant::Capability(c)) => format!("ALLOW — {:?} capability (expires, single-use)", c.primitive),
            Ok(Grant::NeedsHumanApproval(r)) => format!("STEP-UP — human approval required ({r})"),
            Ok(Grant::Proposed(v)) => format!("PROPOSE-NOT-COMMIT — offered `{}` instead", v.as_str()),
            Err(Denied::OriginMismatch) => "DENY — origin mismatch (confused-deputy blocked)".to_string(),
            Err(Denied::Policy(r)) => format!("DENY — {r}"),
        };
        println!("• {desc}\n    [{verb} @ {}] -> {outcome}\n", action.target.0);
    }

    println!("== audit trail (hash-chained, verify()={}) ==", broker.audit.verify());
    for e in broker.audit.entries() {
        println!("  #{} {:<16} {:<18} {}", e.seq, e.item_id, e.origin, e.decision);
    }
}
