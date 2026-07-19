# AGENTS.md — last updated: 2026-07-19
# Keep under 400 lines. Split overflow to memory/ files.

## Working Style
Output format: prose with bold leads; short directives from Felix ("continue",
"fix it", "go for it") mean "build and verify the next increment autonomously".
Decision style: recommend directly, act, and flag the call — do not present menus.
When stuck: make the call and say so. Ask only when the answer changes the work
materially (licence choice, product name, open-core boundary).
Review mode: critique hard. Report failures with the output that shows them.

## Project Context
Company: klarlabs — Keyward, an open-core B2C credential manager.
What we're building: passwords + passkeys + TOTP + family sharing, plus an MCP
broker that lets AI agents USE credentials without ever seeing them.
Phase: prototype, pre-GA. Live at proctor.klarlabs.de (one user), running 1.42.0.
Stack: Rust workspace (13 crates), Vue 3 + Vite + Pinia web vault, WASM bridge,
k3s on Hetzner, Postgres, Traefik, RollOps.

## Constraints
Never: change a crypto domain-separation label or a `keyward.passbook.*`
  localStorage key. FROZEN; changing one breaks decryption or orphans trust
  state on real devices. They were renamed proctor→keyward ONCE, on 2026-07-19,
  while pre-GA with no external installs — that window is closed. The only
  deliberate exception is `LEGACY` in `app/src/lib/trust.ts`, which keeps the
  `proctor.` prefix because it names pre-rename bytes already on disk.
Never: put demo or mock data in application code. Use a docker-compose demo
  environment with seeded data instead.
Never: run scout/browser automation headless — Felix watches it live.
Never: commit on a non-zero lint or test exit. If a check fails, say so.
Always: verify a claimed build/test pass from the command's OWN exit code —
  piping to `tail` returns tail's status, which has produced false "it passed"
  reports in this project more than once.
Always: treat cluster-level infra (cert-manager, ingress controller, DNS,
  metrics-server) as Felix's domain. Document prerequisites; do not provision.
Always: verify a security fix by writing the test that performs the ATTACK, not
  one that confirms the happy path.

## Known Failure Modes
- Tends to trust `memory/status.md`'s plan without re-verifying it against live
  state → its deploy plan was wrong three ways at once (no 2.0.0 image existed,
  the image name pointed at an unpublished ghcr package, and the target namespace
  did not exist), and nothing in the file signalled any uncertainty. Correct by
  treating memory as a LEAD, not a fact, whenever the next step touches
  infrastructure: query the cluster, the registry and the tag list before acting
  on what a note claims is already there.
- Tends to verify config by READING files rather than RENDERING them →
  `metrics-block.yaml` hardcoded the old hostname, and its Ingress matches on host
  AND path, so moving only the primary Ingress would have left `/metrics` falling
  through to the catch-all `/` router and served to the open internet — silently
  reopening the exact hole that file was written to close. The overlay read fine;
  `kubectl kustomize | grep` found it in seconds. Correct by rendering and
  grepping the OUTPUT before any apply, and by treating a resource that matches on
  more than one field as coupled to every field it matches on.
- Tends to report success from a piped command's exit code → correct by checking
  the build/test process status directly, and by quoting real output. Note the
  shell is zsh: `${PIPESTATUS[0]}` is a BASH-ism and expands to empty here. Three
  occurrences on 2026-07-19 alone. The dangerous case is not the empty value but
  the PLAUSIBLE one: `rollops plan … | tail; echo $?` printed a confident
  `PLAN_EXIT=0` from `tail` while rollops itself had failed with "command not
  found". Use `$?` on an unpiped command, or redirect to a file and check.
- Tends to let a mechanical find-and-replace reach production config → the
  Proctor→Keyward rename silently rewrote the live ingress hostname AND the
  container image name, leaving deploy/ pointing at a ghcr package that was
  never published. Correct by diffing deploy/ and checking each renamed EXTERNAL
  identifier (hostname, image, registry path, secret name) against what actually
  exists remotely — a rename only renames things inside the repo. It also renamed
  PROSE but not the IDENTIFIERS it described, twice: `sharing.rs:48` documented
  labels that read `keyward-passbook` while the constants still read
  `proctor-passbook`, and the native-host manifest was FILENAMED
  `com.klarlabs.proctor.passbook.json` while declaring
  `"com.klarlabs.keyward.passbook"` — Chrome requires those to match, so the
  bridge could never have loaded. After any rename, grep the OLD name and
  justify every survivor out loud; "it's only a comment" is how the first one
  survived.
- Tends to assert a platform default instead of checking one, then repeat the
  assertion as if it were established → claimed twice that the ghcr package would
  publish PRIVATE and need setting to internal; it published PUBLIC, inheriting
  from the public repo. Related: told Felix to run a `kubectl get secret -o name |
  grep` to discover the pull-secret name while the overlay named it (`ghcr-pull`)
  in plain text. Correct by reading the manifest or querying the API when the
  answer is one call away, and by saying "I don't know" rather than predicting —
  a confident wrong prediction costs more than a lookup.
- Tends to assume a doc's header matches its body after editing the body →
  correct by re-reading section headers after any status change.
- Tends to check bundled state instead of installed state → wrongly claimed a
  nox threat-model plugin did not exist; correct by querying installed state.
- Tends to delete "stale" duplicates before diffing them → in-tree plugin copies
  were bidirectionally forked; checking first saved ~1500 lines.
- Tends to branch off a stale main → merge blocked as `BEHIND`. Correct by
  branching off fresh `origin/main`, or rebase + force-push before merge.

## Decision Summary
# 3–5 most consequential decisions. Full log in memory/decisions.md
- 2026-07-19: External crypto review gated on PAYING FAMILIES, not on shipping —
  the order 1Password and Bitwarden both followed.
- 2026-07-19: Renamed Proctor → Keyward. Semantics, not trademark: "proctor" is
  owned by exam surveillance, which inverts a privacy product's pitch.
- 2026-07-19: Carried the rename into the WIRE FORMAT — crypto labels and
  localStorage keys — superseding the same morning's decision to freeze them.
  Legal only because nothing was shipped; permanently invalidates all pre-2.0.0
  ciphertext. That window is now closed: FROZEN means frozen.
- 2026-07-19: Deployment is private, server code is not — privatising the server
  would remove the free self-host tier rather than protect anything.
- 2026-07-19: AGPL-3.0 for the whole workspace; the crates therefore cannot be
  embedded in proprietary software, which for a credential manager is intended.

## Active Patterns
- "brief me" → /brief (reads ./memory/status.md)
- "capture" → /capture (writes session log, updates status)
- "/mem-compact" → digest sessions older than 30 days
