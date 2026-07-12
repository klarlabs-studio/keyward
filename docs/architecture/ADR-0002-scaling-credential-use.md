# ADR-0002 — Scaling credential use across providers

> **Status:** Proposed (research complete; not yet implemented) · **Date:** July 2026
> **Context:** [ADR-0001 broker security model](ADR-0001-broker-security-model.md) · [Product Spec §6](../product/product-spec.md)
> **Supersedes nothing. Extends the execution + minting layers of ADR-0001.**

## Context

The wedge (ADR-0001) performs actions on the agent's behalf so the credential
never reaches the model. v1.0.0 does this for one provider over HTTP (GitHub). The
open question: **how does this scale to AWS, GCP, Hetzner, Terraform, kubectl, and
the long tail without turning Proctor into an ever-growing catalog of per-vendor
integrations?**

Naïvely it looks O(N): a bespoke *minter* and a bespoke *executor* per provider.
That is an infinite treadmill and would make the core grow without bound — the
wrong architecture. This ADR establishes that the problem collapses on three
independent axes, grounded in how the industry already solves each one.

## Decision

**Proctor is a policy engine + a generic injector + a declarative profile
registry — not a collection of vendor integrations.** The core does not grow with
the number of providers. Three collapses:

### 1. Coverage never depends on a minter — vault-read is O(1)

Any credential works today via **vault-read**: store the token, use it. Coverage
is never blocked on building a minter or executor. Minting and provider profiles
are purely *additive*. This is the universal fallback the other two axes build on.

### 2. Minting collapses to standard protocols, not vendors

Do not build one minter per cloud. Build a small number of **protocol** minters:

- **OAuth 2.0 Token Exchange (RFC 8693)** — the STS grant
  `urn:ietf:params:oauth:grant-type:token-exchange`; a "token at hand" is
  exchanged for a scoped, short-lived "new token" [S1, S6].
- **OIDC Workload Identity Federation** — AWS STS `AssumeRoleWithWebIdentity`,
  GCP Workload Identity Federation, and Azure Entra all accept an OIDC JWT and
  return short-lived cloud creds using the *same* exchange flow. One held OIDC
  identity federates into **any** cloud that trusts the issuer — the GitHub
  Actions → cloud-STS pattern generalized [S2, S3, S4].

Providers that issue only long-lived tokens (Hetzner, Terraform Cloud, most SaaS
keys) **cannot be minted from** — there is no short-lived-token API — so they are
vault-read by definition. The set of mintable providers is small and
standards-shaped (the big clouds): **~3 protocol minters, not N.**

### 3. Execution collapses to a generic exec-injection executor

Do not implement per-vendor APIs. Ship **one** generic executor: set the
credential into a child process's environment, run the command, capture output,
return only that. The credential is the auth material *inside* the subprocess;
the model gets the result. This is exactly the established `op run` / Vault-Agent
/ `aws-vault exec` pattern — "run the command in a subprocess with the secrets
available as environment variables only for the duration of the process" [S5, S7].
One executor covers **every CLI-driven provider** (aws, gcloud, hcloud, terraform,
kubectl, pulumi) with zero per-vendor code. HTTP-perform (as built for GitHub)
remains for the few cases that warrant a native call.

**The per-provider knowledge is declarative data, not code — and it is keyed on
the credential type, not the tool.** A profile states two things: (a) how the
credential is presented (which env vars), and (b) which invocations mutate. Env
conventions are standardized and *shared across tools*: the AWS credential env
vars (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`) are
identical in the aws-cli and Terraform docs; `HCLOUD_TOKEN` serves both the hcloud
CLI and the Terraform Hetzner provider [S8, S9, S10]. So **one AWS profile serves
aws-cli, Terraform, Pulumi, OpenTofu, and every SDK** — the whole infra world is
~a dozen five-line profiles, not per-tool integrations.

### 4. Command-risk policy — safe when incomplete

Since the agent now controls the *command*, the broker gates the command, not just
the credential, reusing ADR-0001's reversibility × consequence machinery on argv:

- **Default-gate**: a command with no risk profile is treated as mutating →
  step-up / propose-not-commit. Unknown ≠ broken; unknown = asks a human. Coverage
  is never blocked on classification.
- **User allowlist patterns**: e.g. "`aws * ls|describe*|get*` unattended;
  everything else asks." Zero Proctor knowledge required.
- **Optional profiles** (shipped + community) add auto-allow for known-read
  invocations. Convenience scales with the registry; safety does not depend on it.

### 5. A profile registry, not core code

Profiles are declarative, per-provider, community-extensible — a data registry
like Homebrew formulae. The core carries the engine and a small seed set; the long
tail lives in the registry and is safe to be incomplete (missing = gated).

## Security model — the load-bearing caveat

**Environment-variable injection is hygiene, not an isolation boundary.** An
injected secret is readable by any same-UID process via `/proc/<pid>/environ`,
visible in `ps eww`, captured in crash dumps/core files, and **inherited by every
child process** [S11, S12]. A 2026 agent (Hermes) shipped an env-strip "protection"
that was trivially bypassed by reading `/proc/<parent_pid>/environ`; the
maintainer's verdict is the design lesson: *the env-strip is hygiene, not a
boundary — the right posture for untrusted-content workloads is a non-default,
OS-isolated backend; the fix is "pick the right backend," not "sprinkle
namespacing on the local one"* [S13, S14].

For an **agent** — which runs arbitrary commands, some influenced by untrusted
content — this is precisely the threat. Therefore the exec path's safety rests on:

- **Prefer minted short-lived creds on the exec path.** A `/proc` dump of a
  10-minute scoped token is a near-non-event; a dump of a long-lived vault token is
  a breach. Minting (axis 2) directly bounds the exec blast radius [S15].
- **Never put secrets in argv** — `/proc/<pid>/cmdline` is world-readable; inject
  via env or stdin only.
- **OS-level isolation for untrusted contexts** — run the child in a PID/mount
  namespace or container (`unshare --pid --mount-proc`, Docker/Modal/SSH backends)
  so `/proc` scanning and env inheritance don't cross the boundary.
- **Command gating + audit** (axis 4) — the argv is policy-checked and logged.

Honest consequence: **vault-read + subprocess injection exposes a long-lived
credential to the local session.** That is acceptable for a trusted developer
machine running trusted tools; it is *not* acceptable for untrusted-content-driven
autonomy without either minting (short TTL) or OS isolation. The broker must make
this explicit per credential/context, not paper over it.

## Alternatives considered

- **Per-vendor bespoke minters + executors** — rejected: O(N) treadmill, core
  grows unbounded, never catches the long tail.
- **HTTP-perform only** (as built for GitHub) — rejected: can't cover CLI-driven
  tooling (Terraform, kubectl, cloud CLIs) without reimplementing each API.
- **Return the (minted/stored) token to the agent** — rejected: reintroduces
  plaintext into the model context and maximizes exposure; violates ADR-0001.

## Consequences

- The core stays provider-agnostic; what grows is a declarative registry, not code
  Proctor maintains.
- Safety scales for free (default-gate); convenience scales with profiles.
- The exec path's security is explicitly bounded by credential TTL + OS isolation
  + command gating — documented, not assumed.
- Minting becomes higher-value (it now also bounds `/proc` exposure), reinforcing
  ADR-0001's "prefer minted" primitive on the exec path.

## Implementation sketch (phased)

1. **Generic exec-injection executor** — `run_with_credential(command, argv)`:
   env-inject via a provider profile, spawn, capture stdout/stderr, return
   sanitized. Default-gate unknown argv; support user allowlist patterns.
2. **Seed profiles** — AWS, Hetzner, GitHub (`GITHUB_TOKEN`); each ~5 lines.
3. **Standard protocol minters** — RFC 8693 token exchange + OIDC WIF (covers the
   big clouds), reusing the existing `Minter` trait.
4. **OS isolation backend** — optional namespace/container execution for untrusted
   contexts.
5. **Profile registry format** + community contribution path.

## Sources

- **S1** IETF RFC 8693 — OAuth 2.0 Token Exchange. https://www.ietf.org/rfc/rfc8693
- **S2** Google Cloud — Workload Identity Federation (follows OAuth token exchange). https://docs.cloud.google.com/iam/docs/workload-identity-federation
- **S3** Google Cloud — WIF with AWS/Azure (exchange environment creds for short-lived tokens). https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-other-clouds
- **S4** Cross-Cloud OIDC Federation — one identity, any cloud that trusts the issuer. https://www.systemshardening.com/articles/cross-cutting/cross-cloud-oidc-federation/
- **S5** 1Password Developer — `op run` loads secrets as env vars into a subprocess for the duration of the process. https://www.1password.dev/cli/secrets-environment-variables
- **S6** RFC 8693 Deep Dive — token-exchange grant; OIDC federation is the mainstream case. https://dev.to/kanywst/rfc-8693-deep-dive-token-exchange-310i
- **S7** Secret managers 2026 — "move from ambient env vars to exec-time injection changes the risk profile; tool choice is secondary." https://gethasp.com/guides/secret-manager-landscape-2026-8-tools-compared/
- **S8** Terraform AWS provider — standard AWS_* credential env vars. https://registry.terraform.io/providers/hashicorp/aws/latest/docs
- **S9** AWS CLI — supported credential environment variables. https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html
- **S10** Terraform Hetzner provider — `HCLOUD_TOKEN`. https://registry.terraform.io/providers/hetznercloud/hcloud/latest/docs
- **S11** env.dev — env vars are readable via /proc/environ, ps, crash dumps, child processes. https://env.dev/guides/env-vars-security
- **S12** Doppler — environment-variable secrets in 2026. https://www.doppler.com/blog/environment-variable-secrets-2026
- **S13** GitHub Hermes-agent #4427 — /proc/<parent_pid>/environ bypasses env-strip; "hygiene, not a boundary; pick the right backend." https://github.com/NousResearch/hermes-agent/issues/4427
- **S14** Security Scientist — /proc filesystem (T1003.007): environ/mem/cmdline exposure; short-lived tokens limit the damage. https://www.securityscientist.net/blog/12-questions-and-answers-about-proc-filesystem-t1003-007/
- **S15** HashiCorp Vault (dynamic secrets) — short-TTL creds; "even if leaked, expires within hours." https://acquaintsoft.com/blog/secrets-management-aws-vault-devops-implementation
