# Proctor — B2C Password / Credential Manager: Market & Feature Research

> **Status:** Research report v1 · **Date:** July 2026 · **Author:** Proctor product research
> **Scope:** Consumer (B2C) password / credential management. Enterprise (SSO/SCIM/PAM) covered only as context.
> **Sourcing note:** Market-size figures vary widely by analyst. Where sources disagree we present a **range**, not false precision. Inline citations refer to the source list at the end.

---

## 1. Executive summary

The consumer password-manager market is **large, growing, under-penetrated, and — in 2026 — unusually unstable**. That instability is the opening.

- **Size & growth:** ~**$3.0–3.2B** in 2025, growing at a **~15–20% CAGR** toward **$9–14B by 2032–2035** depending on the analyst [S1, S2, S5, S7].
- **Under-penetration:** only ~**36% of US adults (~94M people)** use a password manager, up just ~2 pts YoY [S2]. Critically, **75%+ of non-users say they would adopt one if it balanced security, cost, and usability** [S5] — the single most important demand signal in this report.
- **Incumbent gravity:** Apple Passwords + Google Password Manager together hold **55%+ of usage** by being free and built-in [S5]. They are the real default, not the paid players.
- **2026 turmoil:** Dashlane killed its free plan (Sep 2025); Bitwarden raised Premium **+98%** (Jan 2026); 1Password raised prices **+33%** (Mar 2026, its first consumer increase since 2016); Proton Pass *cut* prices; ETH Zürich researchers disclosed **25+ cryptographic flaws** across three major cloud managers [S8, S9, S12]. Trust and pricing are both in flux.
- **The two structural gaps (and Proctor's thesis):**
  1. **The best UX is proprietary and getting expensive.** 1Password is the consensus polish/UX/family leader — and now has *no free tier* plus a 33% price hike [S8, S13, S16].
  2. **The best open option has degraded UX and weak connectivity.** Bitwarden's 2024–25 browser-extension redesign produced a documented wave of complaints: 20–60s blank loads, added clicks, broken search, laggy autofill [S10, S11 GH#12698].
- **The opening:** an **open-source, 1Password-grade, passkey-era, family-friendly credential manager** with a **user-choosable cloud/on-device trust model** and fair pricing. No incumbent occupies that intersection.

---

## 2. Market sizing & growth

| Metric | Figure | Source |
|---|---|---|
| Global market size (2024) | ~$2.5–2.9B | S2, S5, S7 |
| Global market size (2025) | ~$3.0–3.2B | S2, S5 |
| Projected size (2032–2035) | ~$9–14B | S1, S2, S5, S7 |
| CAGR (consensus band) | ~14–20% | S1, S2, S5, S7 |
| US adults using a password manager | ~36% (~94M) | S2 |
| US non-users open to adopting | 75%+ (if security/cost/usability balanced) | S5 |
| Avg. online accounts per person | 150–200 | S6 |

**Reading the numbers.** The dollar-size forecasts diverge (some analysts include enterprise IAM, some don't) but agree on **mid-to-high-teens CAGR** and a market roughly tripling within a decade. The more actionable metrics are behavioural:

- **Penetration is low and growing slowly.** ~36% adoption means the majority of people still reuse passwords or rely on browser autofill. This is a *conversion* market, not a saturated share-steal market.
- **The category is highly fragmented.** By some measures "Others" account for **~60%** of the paid market [S2] — i.e., no single paid vendor dominates consumers; the built-ins do.
- **The willingness signal is the whole game.** The 75%+ "would adopt if it were the right balance" figure says the barrier is **product experience and value**, not awareness. Awareness of the *problem* is high; the products have failed to convert.

**Implication for Proctor:** win the switchers *and* the not-yet-adopters by beating the built-ins on capability and beating the paid incumbents on the security/cost/usability balance the market says it wants.

---

## 3. Competitive teardown

### 3.1 1Password — the UX & family benchmark (proprietary)
- **Positioning:** premium, polished, "gold standard" security [S13]. The one every reviewer names for families and non-technical users.
- **Pricing (2026):** **no free tier** (14-day trial only). Individual **$3.99/mo ($47.88/yr)**, Families **$5.99/mo ($71.88/yr, up to 5)** after the Mar 2026 +33%/+20% hikes [S8, S9].
- **Architecture:** account password **+ device-generated Secret Key (2SKD)** so a server breach yields uncrackable data [S14]; SRP authentication; end-to-end encryption. **Never breached** — a real differentiator against LastPass [S16].
- **Standout features:** Watchtower (breach/weak/reuse audit, privacy-preserving HIBP), **Travel Mode** (removes vaults from devices at borders — unique), best-in-class family sharing (private + shared vaults, guest accounts, account recovery, multiple organizers) [S13, S15, S16].
- **UX reputation:** the reference point. Autofill "works on almost every website"; a 90-day head-to-head found 1Password succeeding where Bitwarden's autofill failed ~15% of the time [S17].
- **Weaknesses:** proprietary/closed source; no free tier; now the most expensive mainstream option; slight Apple-first bias on Windows.

### 3.2 Bitwarden — the open-source value leader with a UX problem
- **Positioning:** open source (GPL/AGPL), independently audited, unlimited free tier, self-hostable — the developer/value default [S3, S4].
- **Pricing (2026):** Free (unlimited passwords + devices); Premium **$19.80/yr** (after a **+98%** Jan 2026 hike — still cheapest paid); Families **$47.88/yr for 6** (best per-seat deal) [S8, S3].
- **Architecture:** AES-256 with PBKDF2/Argon2id; zero-knowledge; official self-host (heavy, ~1.5–2GB RAM) plus the community **Vaultwarden** server (~50MB) [S4].
- **The problem — documented UX regression:** the 2024.12–2025.x browser-extension redesign triggered massive community backlash. Representative, verifiable complaints [S10, S11]:
  - Vault popup taking **20–60 seconds** to render a blank screen before loading.
  - One-click copy of username/password/TOTP replaced by **two-click dropdowns**.
  - Clicking the site name no longer autofills — now a small "Fill" button.
  - **Search degraded** (per-word filtering instead of phrase matching).
  - General lag/sluggishness; multi-step render "flashing"; endless loading when editing a login's URL [GitHub bitwarden/clients #12698].
  - Users publicly stating they are considering switching to 1Password "while I was always a huge fan of Bitwarden."
- **Takeaway:** Bitwarden validates both the demand for open source *and* the exact functional gap (connectivity, autofill reliability, extension performance, organization) Proctor should own.

### 3.3 Proton Pass — the privacy challenger, rising fast
- **Positioning:** Swiss, privacy-first, part of the Proton suite; increasingly the reviewer pick for *free* [S8, S18].
- **Pricing (2026):** strong Free tier (unlimited logins, 10 aliases, **unlimited passkeys** since Feb 2026); Pass Plus **~$1.99/mo**; Family bundles Mail/VPN/Drive/Calendar. Notably *cut* prices while others raised [S8, S18].
- **Architecture:** **client apps open source (GPL), server closed** ("partly open") [S3]; end-to-end encrypted; XChaCha20; SimpleLogin email aliases built in; Proton Sentinel monitoring.
- **Strengths:** best free tier, integrated aliases, privacy brand, stable/declining price.
- **Weaknesses:** UX rated "good, not great"; standalone value weaker than the bundle; server not open.

### 3.4 The rest of the field
- **NordPass** — cheapest family plan (**~$2.58–2.79/mo for 6**), XChaCha20, Cure53-audited, SOC2/ISO27001, **PCMag Editors' Choice 2026**; from Nord Security. Free tier limited to 1 active device; no built-in TOTP [S8, S18, S19].
- **Dashlane** — **killed its free plan (Sep 2025)**; now ~$64.99/yr+, browser-extension + mobile only, Friends & Family up to 10; bundles VPN. Priced itself out of the value conversation [S8, S18].
- **Keeper** — enterprise-leaning, no real free tier, strong security & PAM extensions, $34.99/yr individual, family ~$6.25/mo [S18].
- **LastPass** — **reputationally damaged**: 2022 breaches, later linked to significant crypto-theft losses. Effectively a migration source, not a competitor to win against [S8].
- **Apple Passwords / Google Password Manager** — **the real incumbents** (55%+ combined usage). Free, built-in, now standalone apps with passkeys and cross-app import via CXF on iOS/macOS 26. Weaknesses: cross-ecosystem friction (Apple↔Windows↔Android), thin sharing/organization, no family-grade admin. The gravity well every challenger must overcome.

### 3.5 The open-source / self-host tier
| Tool | License | Model | Sharing | Notes |
|---|---|---|---|---|
| **Vaultwarden** | GPL/AGPL-3.0 | Bitwarden-compatible server, Docker, ~50MB RAM | Org features | Most popular self-host; uses official Bitwarden clients [S3, S4] |
| **KeePassXC** | GPL-2.0 | Local `.kdbx` file, no server | Via file sync | Offline-first, YubiKey, AES-256/ChaCha20 + Argon2; sync is DIY (Syncthing/Nextcloud) [S3, S4] |
| **Passbolt** | AGPL-3.0 | Team server, OpenPGP per-user keys | Fine-grained, GPG | Team/compliance focus; LDAP/SSO in CE [S3, S4] |
| **`pass`** | GPL | Git tree of GPG files, CLI | Via git/GPG | Unix-philosophy; scriptable/auditable; poor consumer UX [S4] |

**Takeaway:** the OSS tier proves demand for sovereignty and auditability, but every option trades away consumer-grade UX, seamless sync, or polished family sharing. That trade-off is precisely what Proctor removes.

---

## 4. Feature comparison matrix

| Capability | 1Password | Bitwarden | Proton Pass | NordPass | Dashlane | Apple/Google | Vaultwarden | KeePassXC |
|---|---|---|---|---|---|---|---|---|
| Free tier | ❌ (trial) | ✅ unlimited | ✅ strong | ⚠️ 1 device | ❌ (ended) | ✅ built-in | ✅ (self-host) | ✅ local |
| Individual /yr | $47.88 | $19.80 | ~$23.88 | ~$16–24 | ~$64.99 | $0 | $0+VPS | $0 |
| Family /mo | $5.99 (5) | $3.99 (6) | ~$4.99 (6) | ~$2.58 (6) | ~$8 (10) | $0 | $0+VPS | n/a |
| Open source | ❌ | ✅ | ⚠️ client only | ❌ | ❌ | ❌ | ✅ | ✅ |
| Zero-knowledge E2E | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (local) |
| Secret-key layer (2SKD) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | n/a |
| Self-host | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ (file) |
| Passkeys (store/fill) | ✅ | ✅ | ✅ (free) | ⚠️ | ✅ | ✅ | ✅ | ⚠️ |
| TOTP built-in | ✅ | ✅ (paid) | ✅ | ❌ | ✅ | ⚠️ | ✅ | ✅ |
| Email aliases | ⚠️ (integr.) | ⚠️ | ✅ native | ✅ | ⚠️ | ❌ | ❌ | ❌ |
| Security audit (Watchtower-style) | ✅ best | ✅ | ✅ | ✅ | ✅ | ⚠️ | ⚠️ | ⚠️ |
| Emergency access | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ |
| Travel mode | ✅ unique | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Choosable cloud/on-device + migration | ❌ | ⚠️ (either, not seamless) | ❌ | ❌ | ❌ | ❌ | ⚠️ | ⚠️ |
| Agent/LLM credential broker (MCP) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Autofill reliability (reviewer consensus) | ★★★★★ | ★★★☆☆ | ★★★☆☆ | ★★★★☆ | ★★★★☆ | ★★★☆☆ | ★★★☆☆ | ★★☆☆☆ |

Legend: ✅ yes · ⚠️ partial/caveated · ❌ no. Prices are 2026 post-hike figures; see §3 for citations. **Note the last two rows: no competitor offers a choosable-and-migratable trust model or an agent credential broker.**

---

## 5. Pain-point analysis

**1. "The good UX is locked up."** 1Password is the near-universal recommendation for polish and families, but it is proprietary, has no free tier, and just became the most expensive mainstream option. Users who want that experience have no open or lower-cost path to it [S8, S13, S16].

**2. "The open option got worse."** Bitwarden's own community forums and GitHub are full of first-party evidence that the redesigned extension is slow, click-heavy, and unreliable — the exact "OSS is badly connected" complaint that motivated this project [S10, S11]. Autofill failing ~15% of the time in head-to-head testing is a *functional* defect, not a taste issue [S17].

**3. Organization / structure is weak across the board.** Reviewers and forum users repeatedly cite poor search, flat or confusing vault/folder models, and clutter — especially post-redesign. Clean information architecture (tags, smart filters, collections) is an under-served axis.

**4. Ecosystem lock-in fragments families.** The built-ins are free and good *within* one ecosystem but poor across Apple/Windows/Android — which is exactly the mixed-device reality of most households [S18, S19]. Cross-platform family sharing is where paid managers still justify themselves.

**5. Trust is volatile.** LastPass's breaches, the 2026 ETH Zürich crypto-flaw disclosures, and price shocks have primed users to re-evaluate. Auditable, open, breach-clean architecture is a timely wedge [S8, S12, S16].

**6. Agents can't safely use secrets.** An emerging, entirely unserved pain: AI agents increasingly need to log into things, but handing them a password means it leaks into prompts, transcripts, logs, and model providers. No manager offers a safe way for an agent to *use* a credential without seeing it (see §6.3).

---

## 6. Trends shaping the next 3 years

### 6.1 Passkeys go mainstream — the category becomes "credential management"
- **5 billion passkeys** in active use; **90% awareness**, **75%** have enabled at least one, **49%** use them regularly when available [S20].
- The UK NCSC and FIDO Alliance now recommend passkeys as the **default** sign-in method [S20, S21].
- Passwords "refuse to die" — 57% of orgs still use them as primary [S20] — so the winning product manages **passwords + passkeys + TOTP + aliases + identities** together. The product category is shifting from *password vault* → *credential manager*.

### 6.2 Credential portability standardizes (CXP / CXF)
- FIDO's **Credential Exchange Format (CXF)** (Review Draft, Mar 2025) defines a normative JSON structure for passwords, passkeys, TOTP secrets, and notes; **Credential Exchange Protocol (CXP)** (Working Draft, targeting standardization ~2026) defines the HPKE-encrypted transfer [S22, S23, S24].
- Apple shipped same-device CXF import/export in **iOS/macOS 26**; participating managers already include **Apple Passwords, 1Password, Bitwarden, Dashlane** [S22, S23].
- **Implication:** import/export must be CXP/CXF-native, not CSV. Standardized portability *lowers switching costs industry-wide* — good for a challenger courting switchers, provided the product is a first-class CXP participant.

### 6.3 Agentic AI creates a new credential-security problem
- As LLM agents automate browsing, deployment, and account tasks, they need credentials — but pasting secrets into a model context leaks them into prompts, histories, and provider logs.
- There is **no incumbent solution** for letting an agent *use* a credential (fill a field, run an authenticated command) without exposing the plaintext. This is a green-field wedge and directly aligned with the MCP-centric workflow this project already lives in.

### 6.4 Sovereignty & local-first demand
- Steady growth of self-host (Vaultwarden 40K+ stars) and offline-first (KeePassXC) reflects real distrust of cloud custody and price/lock-in fear [S3, S4]. Users increasingly want to *choose* where their data lives — the core of Proctor's architecture.

---

## 7. The opening for Proctor

Synthesis of the above: the market wants a product that no one currently ships — sitting at the intersection of five axes each incumbent only partially covers.

| Axis | Best incumbent | Its gap | Proctor's move |
|---|---|---|---|
| UX / autofill / organization | 1Password | Proprietary, no free tier, pricey | Match the polish; open source; real free tier |
| Openness / auditability | Bitwarden | Degraded UX, weak connectivity | Open + *actually excellent* extension & sync |
| Privacy / aliases | Proton Pass | Server closed, UX "good not great" | Fully open, aliases native, polished |
| Sovereignty | KeePassXC / Vaultwarden | No consumer polish, DIY sync | Choosable cloud/on-device + seamless migration |
| Family | 1Password | Locked behind proprietary premium | Family-first, mixed-skill, open-core pricing |
| **Agent credential use** | **none** | **entirely unserved** | **MCP/CLI credential broker — "hands, not secrets"** |

**Proctor's one-line thesis:** *the password manager that's as polished as 1Password, as open as Bitwarden, as private as you want it — and you decide where your vault lives.* Plus a category-defining capability for the agentic era: let AI use your credentials without ever seeing them.

The product spec (`../product/product-spec.md`) turns this into positioning, architecture, feature set, pricing, and roadmap.

---

## Source list

- **S1** MarkWide Research — Global Password Managers Market ($3.1B 2026 → $10.24B 2035, 14.2% CAGR).
- **S2** SQ Magazine — Password Manager Statistics 2026 (36% US adults / 94M; $3.22B 2025; 15.8% CAGR; market-share splits).
- **S3** PwdFortress / OSSAlt / OpenSourceAlternatives — open-source & self-host landscape (Bitwarden, Vaultwarden, KeePassXC, Passbolt, Proton "partly open").
- **S4** Budget Homelab / Haven Blog — self-hosted comparison (Vaultwarden vs KeePassXC vs Passbolt vs `pass`).
- **S5** technotrenz — Password Manager Statistics 2026 (Apple/Google 55%+; 75%+ non-users willing; market bands).
- **S6** Dataintelo — 150–200 accounts/person; vendor overview.
- **S7** GII Research / Go-Beyond — market-size and CAGR alternates.
- **S8** decodeit.app — "Best Password Managers 2026" (2026 pricing turmoil table; ETH Zürich; LastPass losses; passkey critical mass).
- **S9** tech-insider.org / MacRumors — 1Password Mar 2026 +33% hike specifics.
- **S10** Bitwarden Community Forums — "Usability issues (UX) in redesigned UI (2024.12.0)" and 2025.x megathreads.
- **S11** GitHub bitwarden/clients #12698 — extension render lag; Reddit r/Bitwarden slow-load threads.
- **S12** ETH Zürich (via S8) — 25+ cryptographic flaws across three cloud managers, 2026.
- **S13** WIRED — 1Password Review 2025 (Watchtower, Travel Mode, flexibility).
- **S14** 1Password Security Design white paper / Secret Key & SRP blog posts (2SKD, breach resistance).
- **S15** 1Password Support — About 1Password Families (vaults, guests, organizers, recovery).
- **S16** iSentYou / SaaSCompared — 1Password review 2026 (never breached; price-hike math).
- **S17** pikvue — Bitwarden vs 1Password vs Proton Pass, 90-day test (autofill ~15% failure gap).
- **S18** PCMag/Yahoo, cyberinsider, franklinetech — 2026 family/pricing comparisons.
- **S19** HomeCloudHQ / Security.org — NordPass family pricing & audits.
- **S20** FIDO Alliance — State of Passkeys 2026 (5B passkeys; 90/75/49%).
- **S21** UK NCSC — "Leave passwords in the past" (passkeys as default).
- **S22** FIDO — Credential Exchange Format (CXF) spec + Dashlane CXP support doc.
- **S23** Corbado — CXP/CXF explainer (HPKE; Apple iOS/macOS 26; timelines).
- **S24** FIDO — Credential Exchange Protocol (CXP) working draft.
