# Provider profiles

These are **external, pluggable descriptors** — pure data, no code. Each file
tells Proctor two things about a credential type:

1. **How the credential is presented** to a process (which env var(s)).
2. **Which command invocations mutate** (for the risk gate).

Because env conventions are shared across tools, **one profile serves every tool
that consumes it** — the `aws` profile works for the aws-cli, Terraform, Pulumi,
OpenTofu, and SDKs alike. See [ADR-0002](../docs/architecture/ADR-0002-scaling-credential-use.md).

## Adding a provider (no recompile)

Drop a `<id>.toml` file into your profiles directory (`$PROCTOR_PROFILES`, or
`~/.proctor/profiles`). That's it — GitLab, Azure, Cloudflare, whatever arises.

### Single-token providers

```toml
id = "cloudflare"
description = "Cloudflare API token"
env_var = "CLOUDFLARE_API_TOKEN"
commands = ["flarectl", "terraform"]
read_patterns = ['\b(list|get|show)\b']
mutate_patterns = ['\b(create|delete|update)\b']
```

### Multi-field providers

The vault secret is a JSON object; each field maps to an env var:

```toml
id = "aws"
[env_map]
access_key_id = "AWS_ACCESS_KEY_ID"
secret_access_key = "AWS_SECRET_ACCESS_KEY"
session_token = "AWS_SESSION_TOKEN"
```

## Fields

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Unique profile id; a vault item references it. |
| `description` | no | Human label. |
| `env_var` | one of | Single env var the secret is injected into. |
| `env_map` | one of | JSON-field → env-var map for multi-field credentials. |
| `commands` | no | CLI binaries this profile is typically used with (informational). |
| `mint` | no | Minter kind for short-lived creds: `github-app`, `token-exchange`, `aws-sts`. Omit → vault-read only. |
| `read_patterns` | no | Regexes on the joined argv → **Read** (auto-allow, subject to policy). |
| `mutate_patterns` | no | Regexes on the joined argv → **Mutate** (gated: step-up / propose-not-commit). |
| `allow_shell` | no | Permit a shell interpreter (`sh`, `python`, …) as the run program. **Default false** — a shell runs arbitrary work past command-binding, so it must be opted in explicitly. |

## Safe when incomplete

Risk classification is **default-gate**: an argv that matches no pattern is
`Unknown` and treated as mutating — it asks a human rather than running. So a
profile with thin (or no) patterns is still safe; patterns only add convenience by
auto-allowing known-read commands.
