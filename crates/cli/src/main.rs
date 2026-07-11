//! Proctor CLI — a runnable end-to-end demonstration of the credential broker.
//!
//! Run: `cargo run -p proctor-cli -- demo`
//!
//! It seals a real (Argon2id + XChaCha20-Poly1305) vault, opens it, hands the
//! broker only secret-free metadata, and runs a battery of agent requests
//! through the security model — printing each decision and the tamper-evident
//! audit trail.

use proctor_broker::{Action, ActionVerb, Broker, Denied, Grant, ItemRef, Mode, Policy};
use proctor_vault::{seal, open, Item, ItemKind};
use std::time::SystemTime;

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_else(|| "demo".to_string());
    match arg.as_str() {
        "demo" => demo(),
        other => {
            eprintln!("unknown command: {other}\nusage: proctor demo");
            std::process::exit(2);
        }
    }
}

fn demo() {
    println!("== Proctor broker demo ==\n");

    // 1. A real encrypted vault. The master secret would normally be
    //    master-password + device Secret Key (2SKD); here a passphrase stands in.
    let items = vec![
        Item {
            id: "itm_github".into(),
            label: "GitHub".into(),
            kind: ItemKind::ApiKey,
            bound_origins: vec!["github.com".into()],
            mintable: true, // broker can mint scoped short-lived tokens
            secret: "ghp_do_not_leak_me".into(),
        },
        Item {
            id: "itm_bank".into(),
            label: "Bank".into(),
            kind: ItemKind::Password,
            bound_origins: vec!["bank.com".into()],
            mintable: false, // no minting → broker acts secretlessly
            secret: "hunter2".into(),
        },
    ];

    let master = b"master-password + device-secret-key";
    let sealed = seal(&items, master).expect("seal");
    let opened = open(&sealed, master).expect("open");
    println!("vault sealed & opened: {} items (secrets stay in the vault)\n", opened.len());

    // 2. The broker only ever receives secret-free metadata.
    let refs: Vec<ItemRef> = opened
        .iter()
        .map(|it| {
            let m = it.as_ref_meta();
            ItemRef {
                id: m.id,
                label: m.label,
                bound_origins: m.bound_origins,
                mintable: m.mintable,
            }
        })
        .collect();
    let github = &refs[0];
    let bank = &refs[1];

    let mut broker = Broker::new(Policy::with_approved_origins(&["github.com", "bank.com"]));
    let now = SystemTime::now();

    // 3. A battery of agent requests.
    let scenarios: Vec<(&str, &ItemRef, Action, Mode, bool)> = vec![
        ("agent reads GitHub (bound, reversible, unattended)", github, Action::new(ActionVerb::Read, "github.com"), Mode::Unattended, false),
        ("INJECTED: use GitHub creds on evil.example.com", github, Action::new(ActionVerb::Read, "evil.example.com"), Mode::Unattended, false),
        ("agent wants to ship to prod, unattended", github, Action::new(ActionVerb::ShipToProduction, "github.com"), Mode::Unattended, false),
        ("agent wants to move money, unattended", bank, Action::new(ActionVerb::MoveMoney, "bank.com"), Mode::Unattended, false),
        ("agent wants to move money, human present", bank, Action::new(ActionVerb::MoveMoney, "bank.com"), Mode::Attended, false),
        ("agent demands the raw GitHub secret", github, Action::new(ActionVerb::Read, "github.com"), Mode::Attended, true),
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

    // 4. The tamper-evident audit trail.
    println!("== audit trail (hash-chained, verify()={}) ==", broker.audit.verify());
    for e in broker.audit.entries() {
        println!("  #{} {:<16} {:<18} {}", e.seq, e.item_id, e.origin, e.decision);
    }
}
