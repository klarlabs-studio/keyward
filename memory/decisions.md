---
updated: 2026-07-19
note: append-only log — never edit or delete entries; supersede with "→ superseded [date]"
---
- 2026-07-19: Adopted Agent OS memory system — persistent cross-session state via
  memory/ + wiki/ + cadence skills.
- 2026-07-19: **External crypto review is gated on the managed cloud taking
  PAYING FAMILIES, not on shipping.** 1Password and Bitwarden both shipped first
  and audited later; neither audited before v1, both audited before asking
  families to trust them at scale, and both publish results. (Felix initially
  believed neither had been audited at all — they have, repeatedly, Cure53 for
  both. The valid half of the point was the timing.) Prototype banner stays up
  until the engagement completes.
- 2026-07-19: **Renamed Proctor → Keyward.** Not primarily trademark, though
  PROCTOR is live in class 9 (reg. 1766565) and class 42 (reg. 3743797). The
  decider was semantics: "proctor" is owned by exam-surveillance software, a
  category users actively resent, which inverts the pitch of a privacy-preserving
  credential manager sold to parents and used by teenagers.
- 2026-07-19: **The deployment is private; the server code is not.** Privatising
  sync-server would have removed the free self-host tier rather than protecting
  anything — the same binary runs file-backed with neither Postgres nor Stripe
  configured. Only cluster topology went to keyward-cloud.
- 2026-07-19: **Crypto domain-separation labels and localStorage keys keep the
  `proctor` name permanently.** They are wire and storage identifiers, not
  branding: changing them breaks decryption or orphans trust state on real
  devices. Marked FROZEN in source. → superseded [2026-07-19, same day] — the
  premise was real installs; there were none. See the entry below.
- 2026-07-19: **keyward-cloud pins the public base by commit SHA, not branch.**
  Tracking main would let an unrelated push change what the cluster deploys with
  no commit in the deployment repo to show for it.
- 2026-07-19: **Renamed the crypto labels and localStorage keys to `keyward`,
  superseding the freeze decided the same morning.** The freeze was correct given
  its premise — real installs — but the premise was wrong: one developer vault,
  no external users. Pre-GA with a disposable vault is the only window in which
  this is a rename rather than a versioned format migration with a re-wrap path.
  Knowingly accepted: existing ciphertext, wraps and signatures are permanently
  unreadable, with no migration possible. FROZEN now means frozen — the window is
  closed. Sole exception: `LEGACY` in `app/src/lib/trust.ts`, which keeps the
  `proctor.` prefix because it names pre-rename bytes already on disk.
- 2026-07-19: **The namespace move is a migration, not a rollout, and the repo
  gets CI before it gets a release.** The live install is `proctor/proctor-*`
  while the overlay renders `keyward/keyward-*`, so `rollops apply` would stand
  up a parallel empty stack and report success. Separately, no CI had ever
  existed, so no 2.0.0 image could be built at all — the release process
  documented a pipeline that was never written. Fixed the pipeline rather than
  hand-building the image again.
- 2026-07-19: **Deployment stays gated on a human despite three approvals.** Each
  approval rested on a plan that further investigation invalidated, and the
  remaining steps move zero-knowledge ciphertext with no recovery path. Approval
  of one action is not approval of a materially different one discovered after.
- 2026-07-19: **Deployed 2.0.0 as a clean install on keyward.klarlabs.de, with no
  deprecation window.** The staged both-hosts-live cutover became impossible when
  `proctor.klarlabs.de` was replaced rather than added alongside in DNS — it now
  NXDOMAINs on all three authoritative nameservers. Verified harmless first
  (nothing pointed at it; the label rename had already orphaned every existing
  vault). Consequence to remember: there is no fallback hostname, and re-creating
  one requires a DNS change before anything else can be done.
- 2026-07-19: **The `proctor` namespace stays for ~a week.** Healthy but
  unreachable by name. With the old DNS record gone it is the only surviving
  artifact of the previous deploy; deleting it in the same motion would have left
  nothing to inspect if the new stack misbehaved.
- 2026-07-19: **The metrics-blocking Ingress is HOST-COUPLED to the primary
  Ingress and the two move together.** It matches on host AND path, so a
  hostname change to one alone leaves `/metrics` falling through to the
  catch-all `/` router and served publicly. This nearly shipped; verified in
  production as 403.
