---
updated: 2026-07-19
---
## [OPEN]
- End-to-end vault test on https://keyward.klarlabs.de — create a vault, add an
  entry, reload. The ONLY remaining check that proves crypto round-trips; pods
  and TLS being green does not.
- Re-create the developer vault from its Emergency Kit. The 2.0.0 label rename
  made the old one permanently undecryptable.
- Delete the `proctor` namespace after ~a week of real use on the new stack. It
  is healthy but unreachable; it is also the only artifact of the old deploy.
- Decide the ghcr package visibility. `keyward-sync-server` is PUBLIC by
  inheritance from the public repo; `proctor-sync-server` was `internal`.
- Decide the fate of `memory/`, `wiki/`, `AGENTS.md` in the public repo.
- Native-host bridge renamed to `com.klarlabs.keyward.passbook.json` /
  `keyward-passbook-bridge.sh`, fixing a filename/`name` mismatch that meant it
  could never have loaded. STILL UNTESTED against a real browser.
- Local resolver negative-caches `keyward.klarlabs.de`; verification needed
  `curl --resolve`. Felix's browser may need a DNS flush.
- Logo / visual identity — asked for, never started.
- Same-epoch forks are detected but not resolved.
- Member identity secrets still sit in plaintext localStorage, unlike trust
  state. A device compromise is already fatal, but the asymmetry is odd now.
- `proctor.klarlabs.de` no longer resolves and there is NO fallback hostname. If
  it is ever needed, the DNS record must be re-created first.

## [BLOCKED]
- `rollops apply` and most `kubectl` writes are denied by the permission
  classifier. Reads work via the kubectl MCP; merges and pushes succeed. Any
  future rollout needs Felix at the keyboard or a Bash permission rule.
- External cryptography review — deliberately gated on revenue, not capability.

## [WAITING]
- Trademark clearance on "Keyward" in classes 9 and 42. Nearest known use is
  keyward.io, a small Berlin eng-data startup. Needs a real search, not mine.
