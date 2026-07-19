//! Every place the release version is written must agree.
//!
//! WHY THIS EXISTS: the release workflow already checks the git tag against
//! Cargo.toml and app/package.json — but nothing checked the DEPLOY manifests,
//! and they drifted. `deploy/k8s/deployment.yaml` sat at
//! `keyward-sync-server:1.42.0` through the entire 2.0.0 release. That tag has
//! never existed under the `keyward` name (only the pre-rename
//! `proctor-sync-server` was ever published at 1.42.0), so every OSS
//! self-hoster running `kubectl apply -k deploy/k8s` got ImagePullBackOff.
//!
//! It went unnoticed because the managed-cloud overlay overrides the tag, so
//! the one deployment anybody was watching looked fine. A default that only
//! breaks for people who are not in the room is exactly the kind of thing a
//! test has to hold, because no one will notice it by using the product.
//!
//! Kept as a test rather than a CI step so it runs on every `cargo test`,
//! locally and in Docker, not only on a tag push.

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/sync-server; the root is two levels up.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn read(rel: &str) -> String {
    let p = repo_root().join(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// The workspace version — the single source of truth everything else tracks.
fn workspace_version() -> String {
    let toml = read("Cargo.toml");
    toml.lines()
        .find_map(|l| l.strip_prefix("version = \""))
        .and_then(|rest| rest.split('"').next())
        .expect("[workspace.package] version in Cargo.toml")
        .to_string()
}

#[test]
fn app_package_json_matches_the_workspace_version() {
    let want = workspace_version();
    let pkg = read("app/package.json");
    let got = pkg
        .lines()
        .find_map(|l| l.trim().strip_prefix("\"version\": \""))
        .and_then(|rest| rest.split('"').next())
        .expect("version in app/package.json");
    assert_eq!(
        got, want,
        "app/package.json is {got}, workspace is {want}. The release workflow \
         refuses to publish on a mismatch, so this fails the release rather \
         than shipping a lie."
    );
}

/// Every `ghcr.io/klarlabs-studio/keyward-*` image in the PORTABLE base must be
/// tagged with the current version. The base is what OSS self-hosters apply
/// directly; a stale tag there is broken for them and invisible to us.
#[test]
fn deploy_base_image_tags_match_the_workspace_version() {
    let want = workspace_version();
    let mut wrong = Vec::new();

    for file in [
        "deploy/k8s/deployment.yaml",
        "deploy/k8s/web-deployment.yaml",
    ] {
        for line in read(file).lines() {
            let Some(idx) = line.find("ghcr.io/klarlabs-studio/keyward") else {
                continue;
            };
            let reference = line[idx..].split_whitespace().next().unwrap_or_default();
            // Strip any digest pin before reading the human tag.
            let human = reference.split('@').next().unwrap_or(reference);
            let Some((image, tag)) = human.rsplit_once(':') else {
                continue;
            };
            if tag != want {
                wrong.push(format!("{file}: {image} is tagged {tag}, want {want}"));
            }
        }
    }

    assert!(
        wrong.is_empty(),
        "deploy manifest image tags disagree with the workspace version:\n  {}\n\n\
         These are the defaults OSS self-hosters get from \
         `kubectl apply -k deploy/k8s`. The managed overlay overrides them, so a \
         stale tag here breaks only the people who are not in the room.",
        wrong.join("\n  ")
    );
}
