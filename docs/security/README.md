# Keyward — Security Review Package

> **Status:** prepared for an external review that has **not yet happened.**
> Nothing in this directory should be read as evidence that Keyward's
> cryptography has been audited. It has not. The sharing module says so about
> itself (`crates/passbook/src/sharing.rs:23-24`: *"prototype crypto of the
> *shape*. Needs a formal review before real use"*), and this package exists to
> make that review fast and cheap.

## What this is

A self-contained briefing for a cryptography reviewer engaging with Keyward's
consumer password manager (**Passbook**), its **family sharing** protocol, and
the **zero-knowledge relay** that carries them. It is written from the code, not
from the design intent — where the two diverge, the divergence is recorded.

## The documents

| File | What it answers |
|---|---|
| [`cryptography-spec.md`](cryptography-spec.md) | *What exactly is implemented?* Every construction: algorithm, parameters, wire format, domain-separation labels, key lifetimes. Plus an end-to-end data flow for a full share. |
| [`threat-model-passbook.md`](threat-model-passbook.md) | *Who are we defending against, and where are the boundaries?* Assets, trust boundaries, adversary classes, a STRIDE table, and an explicit list of what is **not** defended. |
| [`known-limitations.md`](known-limitations.md) | *What do we already know is weak?* The honest list, stated without hedging. Read this before the spec if you only have an hour. |
| [`review-scope.md`](review-scope.md) | *What are we asking you to do?* Priority-ordered questions, file/function pointers with line numbers, explicit out-of-scope, and the artifacts provided. |

There is also an **older, separate** document in this directory,
[`THREAT-MODEL.md`](THREAT-MODEL.md), which covers a *different* bounded context:
the AI **credential broker** (`keyward-broker` / `keyward-mcp`). It is not part of
this engagement and is not superseded by these files. Where the two overlap
(shared `keyward-crypto` kernel) this package is the more current description.

## How to use it

**If you are the reviewer, in order:**

1. `known-limitations.md` — calibrates expectations in ~10 minutes. Several
   items there are things we believe are wrong, not merely unproven.
2. `review-scope.md` §1 — the priority-ordered questions. If your budget only
   covers the first three, those are the three that matter.
3. `cryptography-spec.md` — the audit target. Read alongside the code; every
   claim carries a `file:line` pointer so you can verify rather than trust.
4. `threat-model-passbook.md` — for judging whether the *design* answers the
   *problem*, separately from whether the *code* answers the *design*.

> **Filename note.** The threat model would naturally be `threat-model.md`, but
> on a case-insensitive filesystem that name collides with the pre-existing
> `THREAT-MODEL.md` (the credential-broker document, described below). The
> Passbook/sharing threat model therefore carries the longer name.

**If you are a Keyward contributor:** these documents are normative for what we
claim publicly. If you change a construction, a parameter, a label, or a wire
format, update `cryptography-spec.md` in the same change. If you find a weakness,
add it to `known-limitations.md` rather than to a private issue.

## Ground rules for this package

- **No claim of audit.** No external review has been performed on the Passbook
  or sharing cryptography as of this writing.
- **No invented parameters.** Where the code left something ambiguous, the spec
  says so in an *Open question for the implementer* note instead of guessing.
- **No overstatement.** "Zero-knowledge" is used only where the relay
  demonstrably holds no key material, and the metadata it *does* learn is
  enumerated rather than glossed.

## Version and line-number drift

Prepared against the working tree at `main` (post-v1.35.0), **uncommitted**. The
exact commit must be recorded by whoever transmits this package to a reviewer —
without it the `file:line` pointers cannot be trusted.

Two changes landed *while this package was being written*, and are reflected in
it:

- **Recovery contacts** (`SealedBox` / `seal_to` / `open_sealed` in `sharing.rs`,
  plus the client flow in `app/src/lib/sharing.ts`). This is the newest and
  least-examined code in scope. It reuses the existing wrapping-key derivation
  and moves a 2SKD factor off the device — see `cryptography-spec.md` §5b,
  `known-limitations.md` §2a and §10a, and question Q8 in `review-scope.md`.
- **Family-sharing funnel metrics** in the sync server, which closed a
  documentation/implementation mismatch noted during writing.

Because the code is moving, **verify line pointers before relying on them**. The
constructions, labels, parameters, and wire formats described here are the stable
part; the line numbers are not.
