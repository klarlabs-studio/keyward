# Keyward — Product Specification (PRD)

> **Status:** Spec v2 (post-strategy session) · **Date:** July 2026 · **Owner:** Felix Geelhaar / klarlabs
> **Companion:** [Market & Feature Research](../research/market-and-feature-research.md)
> **Repo:** `klarlabs/oss/keyward` · **Model:** open-core
> **v2 note:** Reflects the Socratic strategy session — wedge-first sequencing, hardened broker security model, propose-not-commit autonomy floor, and choosable-hosting reframed as a trust instrument. See §14 decisions log.

---

## 1. Vision & thesis

**Keyward is the credential manager that's as polished as 1Password, as open as Bitwarden, and as private as you want it — because you decide where your vault lives.**

It closes two structural gaps: the best UX (1Password) is proprietary and now expensive, and the best open option (Bitwarden) has degraded connectivity and organization. Keyward closes both, adds a first-class **passkey-era credential model** and **family-first sharing**, a **choosable/migratable cloud-or-on-device trust model**, and a category-defining capability for the agentic era: an **MCP credential broker that lets AI *act* with your credentials without ever possessing them.**

**North-star outcome:** a person (and their family) protects every account with a manager they actually enjoy — hosted wherever they trust — while their agents can act on their behalf with a blast radius that stays small even when every human control fails.

---

## 2. Strategy: who we beat, in what order, and why anyone switches

### 2.1 The real incumbent is "default," not a competitor
Apple Passwords + Google Password Manager hold **55%+ of usage** by being free and built-in; only 36% of adults use a dedicated manager (see research §2). We are fighting *inertia*, not primarily other vendors.

### 2.2 Switching drivers: qualifiers vs. pulls
- **Price and trust are *qualifiers*** — they get Keyward onto the shortlist and prevent rejection. They do **not** supply the energy to uproot a digital life. Every challenger claims them.
- **Capability is the *pull*** — a must-have you can't get elsewhere. Amplified by **trigger events** (price hike, breach, new device) that put someone *in market*.
- Therefore we lead with a **capability no one else has** and treat price/trust/openness as the qualifying foundation.

### 2.3 Sequence: B-then-A (wedge-first)
- **Phase B (wedge, first):** the **AI credential broker** for **developers** — the one capability that is both unowned and a genuine pull. It also directly serves the founder's own workflow (dogfoodable from day one). A *good-enough* vault sits under a *killer* broker.
- **Phase A (mainstream, second):** broaden the vault into the **polished all-in-one family product**, once the wedge has earned attention, revenue, and word of mouth.
- **Why this order:** the horizontal all-in-one is a multi-year polish war against 1Password's decade of lead; attacking it head-on from a standing start is a losing trade. The broker is small, sharp, shippable, unowned, and screenshot-worthy — it earns oxygen first.
- **Non-negotiable bar for the *other* half at each phase:** in Phase B the vault under the broker must be trustworthy and unembarrassing; in Phase A "simple all-in-one" alone won't move anyone, so the family engine (§2.4) must carry it.

### 2.4 The family engine: delegated trust, not a feature
Families do **not** switch as independent rational actors, and **no feature in Keyward speaks to a non-technical parent** — the broker is meaningless to them and "simple all-in-one" is table stakes 1Password already owns. Households switch through **delegated trust**: one competent, trusted person decides and does the work for everyone. That person is the **wedge-B developer** — already on Keyward for the broker, and the household's de-facto IT department.

**Engine = champion-led adoption + frictionless migration + trigger events.** The pull is felt by the *champion*, not the family; the family follows on trust in the person. Product implications (Phase A priorities): make the organizer's job trivial (bulk family setup, guided per-member onboarding for non-technical people, one-click CXP/CXF import, account recovery) and build a strong invite/virality loop. This is 1Password Families' quiet genius — Keyward must match and beat it.

---

## 3. Positioning & category

- **Category:** consumer **credential manager** — not a "password vault." Target
  credential types: passwords, TOTP, secure notes, cards, identities (all
  shipped) plus passkeys, email aliases, and secure documents (planned).
- **Model:** **open-core** — fully open-source clients + server (self-host free forever); revenue from managed cloud, family/premium features, and the broker.
- **Primary market:** B2C — **developers first (wedge), families second (mainstream).** Not enterprise PAM.
- **Positioning statement:**
  > *For people who want serious credential security without lock-in — and for the developers who want their agents to act without leaking secrets — Keyward is an open-source credential manager that delivers 1Password-grade polish, lets you choose where your vault lives, and lets your agents get hands, not secrets. Unlike 1Password (closed, no free tier) or Bitwarden (open but clunky), Keyward refuses the trade-off between polish and openness.*
- **Taglines:** "Your credentials, your rules." · For the broker: **"Give your agents hands, not your secrets."**

---

## 4. Target personas

| Persona | Who | Core need | Role in strategy |
|---|---|---|---|
| **The AI-native builder** (wedge) | Runs coding agents/automations (like Felix) | Agents that act with secrets safely | **Phase-B beachhead + household champion** |
| **The switcher (power user)** | Leaving Bitwarden (UX) or 1Password (price/lock-in) | Reliable autofill, clean org, no lock-in | Early adopter + often the champion |
| **The family organizer** | Manages security for a mixed-skill household | Simple sharing, recovery, onboarding | **Phase-A engine driver** |
| **The non-technical family member** | Partner/parent/kid | "It just works," no jargon, no decisions | Adopts via delegated trust |
| **The privacy maximalist / homelabber** | Distrusts cloud custody | Self-host, offline, auditable | Validates trust; uses sovereignty options |

---

## 5. Choosable & migratable trust model (architecture)

### 5.1 Reframed: choice is a *trust instrument*, not a switching driver
Users do not switch *for* "choose your storage backend." The value of choosability is **trust**: Keyward *can't* lock you in and *can't* be your single point of failure — you *could* self-host or go local anytime. Like open source, the *option* reassures the 95% who never exercise it (the Bitwarden/Proton effect). Therefore:

- **Opinionated default for everyone:** **cloud E2E + device-generated Secret Key** — simple, recoverable, 1Password-grade. This preserves the "super simple" north star; a family faces **no trust-model decision.**
- **Progressive disclosure** for the minority who ask: on-device-only, self-hosted server, bring-your-own-storage (iCloud/Dropbox/WebDAV/S3). These mostly do their job just by *existing*.

### 5.2 Storage modes
| Mode | Where data lives | Account? | For |
|---|---|---|---|
| **Managed cloud (default)** | Keyward hosted E2E sync | Yes | Everyone; families |
| **On-device only** | Local encrypted DB/file | No | Sovereignty/offline (advanced) |
| **Self-hosted** | User's own Keyward server | Yes (theirs) | Homelab/full control |
| **Bring-your-own storage** | User's cloud (iCloud/Dropbox/WebDAV/S3) | No Keyward account | Cross-device without our server |

### 5.3 Cryptography
- **Cloud & self-host:** account password **+ device-generated Secret Key** (two-secret key derivation, à la 1Password) → a **server breach yields uncrackable data even against weak passwords.** The strongest posture in the category and a direct answer to the LastPass / ETH-Zürich trust climate.
- **KDF:** Argon2id (tuned, upgradeable). **AEAD:** XChaCha20-Poly1305 (fast on mobile; AES-256-GCM where HW favors it).
- **On-device-only:** may run master-password-only (no server to breach), optional keyfile/YubiKey.
- **Sharing:** per-recipient public-key envelope encryption; server never sees shared plaintext.
- **Passkeys/WebAuthn (PLANNED, not yet built):** first-class encrypted items,
  sync-fabric-agnostic. The vault reserves a `has_passkey` field and the UI
  renders a passkey line, but no WebAuthn create/get path exists yet — nothing
  can currently create or use a passkey. Tracked as its own work item.

### 5.4 Seamless migration — and the honest caveat
The vault is E2E-encrypted client-side *before* it touches any backend, so changing where it lives is a **re-point + key-rewrap**, never a destructive re-encrypt. CRDT/oplog vault model for conflict-free merges.

**Honest caveat that the migration UX must surface:** the *data* moves seamlessly, but the *trust and recovery model changes at every hop* — on-device → cloud **creates** a Secret Key and recovery obligation; cloud → on-device **destroys** it (and with it, any cloud recovery path). Migration flows must make the changed recovery story explicit, not hide it.

**Recovery footgun (must be designed against):** on-device-only with no escrow means a lost device or forgotten master password = permanent, unrecoverable loss. On-device-only is therefore **advanced, gated behind clear warnings and an exported Emergency Kit**, never a casual default.

### 5.5 Recovery & threat model
- **Emergency Kit** (account password + Secret Key + recovery code); printable, 1P-style onboarding.
- **Family/social recovery:** ≥2 organizers can recover a member; no party sees plaintext.
- **Lost-device:** per-device keys, de-authorization, remote wipe of local caches.
- **Documented threats:** server breach (defeated by Secret Key), curious/malicious host, lost device, phishing (passkeys + origin-bound fill), and — for the broker — prompt-injection / confused-deputy / legitimate-but-catastrophic action (§6).

---

## 6. AI-native credential broker (the wedge)

> "Give your agents hands, not your secrets."

### 6.1 Problem
Agents increasingly must log in, use API keys, and run authenticated commands. Pasting a secret into an LLM leaks it into prompts, transcripts, logs, and model providers. No manager addresses this.

### 6.2 Design principle: minimize blast radius *by construction*, not by vigilance
The secret being invisible to the model is necessary but the *easy 20%*. The real goal: **when every human control fails — rubber-stamped, or nobody watching — what leaks must be small, short-lived, and useless elsewhere.** Two harder threats drive the design:
- **Confused deputy / prompt injection:** the *agent* requests the action and can be manipulated (via a poisoned page/repo/doc) into using the right secret against the *wrong* target. Hiding plaintext does nothing here.
- **Legitimate-but-catastrophic action:** a correctly-scoped credential, used exactly as authorized by a mistaken/manipulated agent, does something irreversible (delete prod DB, ship a broken release). The *authority itself* — not the secret — is the vulnerability.

### 6.3 The default primitive (in preference order)
1. **Mint just-in-time credentials.** Exchange the stored secret for a fresh, narrowly-scoped, short-TTL credential; hand the agent only that (GitHub fine-grained/App tokens, cloud STS `AssumeRole`, OAuth 2.0 Token Exchange RFC 8693 — the Vault "dynamic secrets" pattern). A leaked 10-minute scoped token is a non-event.
2. **Secretless / broker-performed action.** When minting isn't possible (legacy password login), the agent gets a **handle**; the *broker* performs the action (origin-bound injection, or attaching the secret to an outbound request the agent configured but can't read). Secret never leaves the broker process.
3. **Raw durable secret** — last resort, off by default, hardest gate.

### 6.4 Defense-in-depth layers
- **Origin/target binding** — capability is bound to a specific origin; the broker **refuses** a mismatch regardless of approval. This is what actually kills the `evil.example.com` attack (same insight that makes passkeys phishing-resistant). Binding beats confirmation because it doesn't depend on human alertness.
- **Capabilities with caveats** — every grant scoped on `item × origin × TTL × use-count × action-scope` (macaroon/biscuit style; only narrows, never widens).
- **Risk-tiered policy** — so confirmation stops being theater: **auto-allow** narrow/reversible/short-TTL to pre-approved origins; **step-up approval** (target shown front-and-center, high-risk styled distinctly) for novel origins, durable secrets, prod scope; **hard-deny by default** raw-secret export. Confirmation becomes a *rare, meaningful* escalation.
- **Process isolation** — broker is a separate local process; key material in OS keychain/Secure Enclave; MCP surface exposes verbs + handles only; not network-exposed by default.
- **Audit + kill switch** — append-only tamper-evident log (who/what/when/item/origin/scope); instant revoke-all; anomaly auto-revoke (burst, new origin, odd hour).

### 6.5 Autonomy floor — propose-not-commit
Scope/TTL shrink the blast radius of a *leak*; they do nothing for a *legitimate-but-catastrophic action*. The deciding axis is **reversibility × consequence**, not credential narrowness.

**Design:** shape *minted* credentials so the agent **cannot commit an irreversible action** — it can *open* a deploy PR but not *merge*, *draft* an email but not *send*, *stage* a transaction but not *settle*. Unattended autonomy is broad; every high-consequence output lands as a **reviewable artifact** awaiting a human.

**The tension relocates (and these become requirements):**
1. **Capability-risk policy layer** — an explicit taxonomy classifying every action class by reversibility/consequence and minting credentials that enforce it. Where a service offers no propose/commit split (send email, charge card, delete object), fall back to human-gate or accept-with-guardrails — there is no free lunch.
2. **Fatigue-fighting review queue** — batched/async review is better than mid-loop popups, but rubber-stamping 40 PRs is approval fatigue in disguise. The queue must risk-rank, surface diffs, and make the one dangerous item *look* dangerous.
3. **Irreducible residue** — irreversible + time-critical + must-run-unattended actions (e.g. emergency credential rotation at 3am) have no proposable form; grant with tight guardrails + loud out-of-band alerts, or forbid unattended. A conscious floor.

**Never-unattended list (locked default; user-editable):** deleting/destroying data · moving money · publishing/releasing to production · sending outbound comms as the user (email/DM) · rotating or revoking *other* credentials.
**Broadly-unattended (reversible/proposable):** reading · running tests · fetching data · opening PRs/drafts · staging changes · minting further *narrow read-scoped* tokens.

### 6.6 Unattended mode
Not "approve everything" — a **pre-authorized policy**: specific items/origins, tighter TTLs, hard per-run caps, and **out-of-band alerts** on every high-risk use. Autonomy and safety reconcile via pre-scoped policy + async notification, not synchronous clicking.

### 6.7 MVP broker scope
Mint for the top services (GitHub, cloud) · origin-bound injection for password logins · capability scoping (`item × origin × TTL × count`) · risk-tiered approval · propose-not-commit with the locked never-unattended list · audit + kill switch. Raw-secret export, full anomaly detection, and broad service coverage come later.

---

## 7. Feature set — by phase

### Phase B — wedge (developer-first)
- **Broker MVP** (§6.7) as the headline — MCP server + CLI, first-class.
- **Good-enough vault:** passwords, TOTP, secure notes, cards, identities, API keys/dev secrets; managed-cloud + on-device storage; Secret Key crypto; Emergency Kit. (Passkeys are a separate, not-yet-built work item — see above.)
- **Chromium extension** meeting the connectivity/latency bar (see §8); web + macOS + iOS (founder's ecosystem).
- **Import:** CXP/CXF where available + CSV/1PUX/Bitwarden JSON.
- **Security dashboard** (weak/reused/breached/2FA-available).

### Phase A — mainstream (family broadening)
- **Family engine:** private + shared vaults, guest single-item share, **account/social recovery**, granular permissions, **bulk family setup + guided per-member onboarding**, invite/virality loop (§2.4).
- **Polish + reach:** Firefox/Safari extensions, Windows/Linux/Android, native OS autofill providers.
- **Sovereignty options:** self-hosted server + BYO-storage, **seamless migration UX** across all modes (§5).
- **Depth:** native email aliases, Watchtower-style depth, breached-password *fixing/rotation*, travel-mode-style vault hiding.

---

## 8. Platform strategy
First-class surfaces, sequenced: **Phase B** — MCP server + CLI, web vault, Chromium extension, macOS, iOS. **Phase A** — Firefox/Safari, Windows/Linux, Android. Autofill/connectivity is make-or-break: invest disproportionately in extension speed (target < 150ms to interactive — a direct rejection of Bitwarden's regression), one-click copy/fill, and native OS autofill (iOS AutoFill, Android Credential Manager, Apple Passwords CXF interop). **KPI: beat Bitwarden's ~15% autofill-failure gap; approach 1Password reliability.**

---

## 9. Pricing & packaging (open-core)
Land **between Bitwarden (cheapest) and 1Password (premium)** while offering what neither does (broker, choosable hosting).

| Tier | Price (indicative) | Includes |
|---|---|---|
| **Self-host / on-device** | **Free forever** | Full OSS clients + server; all core; you host |
| **Free (managed)** | **$0** | Real free tier: unlimited passwords/devices, passkeys, TOTP, 1 shared vault (unlike 1Password) |
| **Individual** | **~$2.5–3/mo** | Security dashboard, aliases, priority sync, extra storage, **broker access** |
| **Family** | **~$3.5–4.5/mo (up to 6)** | Full family sharing, recovery, guest sharing, admin — undercut 1Password, match Bitwarden per-seat value |

Principles: **no free-tier removal games** (learn from Dashlane) · **transparent, stable pricing** (learn from 2026 hikes) · self-host always free. Broker is a paid-tier capability (the wedge monetizes early with developers).

---

## 10. Roadmap (B-then-A)

| Phase | Theme | Key deliverables |
|---|---|---|
| **0 — Foundations** | Crypto + vault engine | Portable E2E vault, 2SKD Secret Key, KDF/AEAD, CRDT oplog, threat model + audit plan |
| **1 — Broker wedge (B)** | Developer beachhead | Broker MVP (§6.7), good-enough vault, Chromium ext + web + macOS + iOS, imports, security dashboard, **paid broker tier** |
| **2 — Trust & sovereignty** | Choosable hosting | Self-host server, BYO-storage, seamless migration UX, external security audit |
| **3 — Family engine (A)** | Mainstream crossing | Sharing/recovery, bulk family setup + onboarding, invite loop, aliases, Windows/Linux/Android, Firefox/Safari |
| **4 — Depth** | Retention & moat | Breached-password fixing/rotation, broader broker service coverage, anomaly detection, travel mode |

**Status:** **v0.1.0 shipped** the Phase-1 core end-to-end — file-backed vault + CLI, the broker security model, minting (mock + real GitHub App), and a vault-backed MCP server (24 tests). Remaining Phase-1 items: secretless execution, step-up via MCP `elicitation`, browser/native surfaces. See [CHANGELOG](../../CHANGELOG.md).

---

## 11. GTM
- **Motion:** OSS community-led + PLG. Open repo, public roadmap, reproducible builds, published audits (trust as the *qualifier*).
- **Wedge launch (B):** ship the **broker** to the AI/dev community for outsized attention — "give your agents hands, not your secrets." Monetize developers early.
- **Family crossing (A):** **champion-led** — the developer-in-the-household onboards the family; every member = a retained seat. Invest in the invite loop and organizer ergonomics.
- **Trigger campaigns:** "Leaving Bitwarden's new extension?" / "1Password raised prices again?" — CXP-native one-click migration turns *triggers* into switches.

---

## 12. Success metrics
- **Wedge (B):** broker activation (first successful agent action), developer WAU, paid-broker conversion.
- **Product health:** autofill success rate (beat Bitwarden's ~15% gap), extension time-to-interactive (< 150ms).
- **Family (A):** seats activated per champion, family-invite completion, CXP-import completion.
- **Trust:** migration completion in both directions; zero credential-exposure incidents via the broker.

---

## 13. Risks & mitigations
- *Autofill reliability is the whole consumer product* → treat fill failures as sev-1.
- *Broker misuse / confused-deputy / catastrophic action* → origin binding + ephemeral minting + propose-not-commit + never-unattended list; ship conservatively; external review before broker GA.
- *Crypto correctness* → standard primitives only, external audit before GA.
- *Choice-as-burden vs. simplicity* → opinionated default + progressive disclosure (§5.1); on-device-only gated behind warnings.
- *Apple/Google default gravity* → win via capability (broker) + cross-ecosystem family sharing + delegated-trust virality.
- *Two-audience trap* → sequence B-then-A; never build both at full strength at once.
- *Open-core monetization tension* → monetize convenience + family + broker; never core security; self-host stays free.

---

## 14. Decisions log (this session)
- **Sequencing:** B-then-A (broker wedge → family broadening). *Rationale:* capability is the only real switching pull; the broker is the unowned capability; horizontal all-in-one is an unwinnable head-on war.
- **Switching model:** price + trust = qualifiers; capability = pull; family pull = delegated trust via a household champion.
- **Broker:** minimize blast radius by construction; default primitive = mint ephemeral scoped / secretless; durable secret = last resort.
- **Autonomy floor:** propose-not-commit; locked never-unattended list (§6.5).
- **Architecture:** choosable hosting = trust instrument; opinionated cloud-E2E-+-Secret-Key default + progressive-disclosure sovereignty; migration surfaces the changed recovery model.

### Still open (owner: Felix)
- **Brand/name** "Keyward" — trademark + domain check.
- **Mobile stack** — recommend shared Rust crypto/vault core + native UI shells.
- **License** — recommend AGPL-3.0 server + GPL/MPL clients.
- **Audit partner** — Cure53 / Trail of Bits before broker & crypto GA.
- **Free-tier generosity dial** — how much managed-free without cannibalizing paid.
