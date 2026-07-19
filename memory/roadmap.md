---
updated: 2026-07-19
---
## Now
- Deploy 2.0.0 to the cluster (Secret rename + rollout).
- Trademark clearance on "Keyward", classes 9 and 42.

## Next
- Hostname migration proctor.klarlabs.de → keyward.klarlabs.de, in order: add
  record → cert-manager issues → serve both → redirect old → drop old.
- Cut a v2.0.0 tag and pin keyward-cloud's overlay to it instead of a commit SHA.
- Logo and visual identity (never started — the name research superseded it).

## Later
- External cryptography review of sharing.rs. Hard gate before paying families.
- Move the member identity secret (X25519 + Ed25519) out of plaintext
  localStorage into the encrypted vault, as trust state now is.
- Resolve, not just detect, same-epoch forks.

## Done
- F2 closed: signed wrapped-key sets, monotonic epochs, fork detection.
- Trust state moved into the synced encrypted vault, with legacy migration.
- Safety number extended to cover Ed25519 signing keys (label v1 → v2).
- Plain-HTTP sync servers refused (device token was going out in clear).
- Renamed Proctor → Keyward; repos created and split public/private.
- AGPL-3.0 LICENSE added — the workspace claimed it, no file backed it.
