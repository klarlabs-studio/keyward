# Keyward — managed-cloud deployment

This directory deploys **both halves** of Keyward to Kubernetes:

| Component | Source | Image | Serves |
|---|---|---|---|
| **Sync server** | `crates/sync-server` | `keyward-sync-server` | the zero-knowledge sync + family-sharing relay (an API) |
| **Web vault** | `app/` (Vue 3 + Vite) | `keyward-web` | the browser client, as static files behind nginx |

They are deployed to **two different hostnames, on purpose**. That is a security
decision, not a packaging convenience — see
[Which origin serves the vault](#which-origin-serves-the-vault).

> **Historical note, so nobody re-derives this the hard way.** For a while the
> managed instance ran the sync server *only*. It is an API relay: it has no
> route for `/`, so the request fell through to the route table's catch-all and
> the deployment answered a bare `not found`. There was no way to actually use
> Keyward in a browser except cloning the repo and running `npm run dev`. The
> web image and the manifests below exist to fix that.

> **Open-core note.** This Kubernetes deployment is the **paid, managed-cloud
> target**. Self-hosting the sync server stays **free** — run the binary or the
> image anywhere you like. This `deploy/` subtree is provided so the managed
> offering and self-hosters share one reviewed, production-grade path.

> **Zero-knowledge.** The server only ever stores **ciphertext**: opaque
> sealed-vault blobs, opaque wrapped group keys, published public keys, and
> **hashed** invite codes and device tokens. No plaintext, master password, or
> Secret Key ever reaches this process. A breach of the server or its `/data`
> volume yields no usable secrets. See
> [`docs/architecture/ADR-0004-family-sharing.md`](../docs/architecture/ADR-0004-family-sharing.md).

## Architecture

TLS is terminated at the **ingress** (cert-manager + nginx-ingress). The Rust
server itself speaks **plain HTTP** on port `8787` *behind* the ingress and is
never exposed directly — there is deliberately no TLS in the server process.

```
                                                    ┌─▶ keyward-web  Service ─▶ nginx pods :8080   (static SPA)
browser ─HTTPS─▶ nginx-ingress (TLS via cert-manager)┤
                                                    └─▶ keyward-sync Service ─▶ app pods :8787 ─▶ PostgreSQL
```

Note what is **not** in that diagram: an arrow from the web pods to the sync
pods. The nginx tier proxies nothing. It hands the built SPA to the browser, and
the **browser** then calls the sync API directly — cross-origin — from the user's
machine. The web tier is not in the API request path at all, which is why it
needs no service discovery, no secrets, and no NetworkPolicy egress rule.

The managed cloud uses the **PostgreSQL backend** (`KEYWARD_SYNC_PG`), so the API
is **stateless and horizontally scalable** — many replicas behind the Service, all
reading one database (`k8s/postgres.yaml` bundles a simple in-cluster Postgres; for
production point `KEYWARD_SYNC_PG` at a managed DB / operator instead). The
file-backed path (`KEYWARD_SYNC_DIR`) remains for single-node self-hosting.

## Which origin serves the vault

This was the first decision to make and it is the one with real consequences, so
the reasoning is recorded rather than just the outcome.

**The two options.** Serve the SPA from the *same* origin as the sync API
(`keyward.example` serving both `/` and `/v1/*`), or from a *separate* origin
(`app.keyward.example` for the SPA, `sync.keyward.example` for the API).

**Decision: separate origins.** `k8s/web-ingress.yaml` gets its own hostname and
its own certificate.

### Why

**1. The vault origin is the crown jewel, and its value is entirely about the
origin boundary.** `docs/security/known-limitations.md` §10 lists three secrets
held as *plaintext strings* in `localStorage`: the device Secret Key (a 2SKD
factor), the member X25519 secret, and the device bearer token. It states the
consequence without hedging — *"Any XSS or malicious browser extension on the app
origin is total compromise."* There is no `SubtleCrypto` non-extractable key
usage and no OS keychain on the web path. `localStorage` is partitioned **per
origin**, so "which origin" is precisely "who can read the Secret Key."

**2. A shared origin puts the API's entire output surface inside that boundary.**
On one origin, *any* sync-server response that a browser could be made to
interpret as HTML — a reflected error page, a future admin view, a billing
redirect landing page, a `Content-Type` slip — executes with full read access to
the vault's `localStorage`. Split, the vault origin serves **only bytes we
authored and froze at release time**: a hashed JS bundle, a CSS file, a WASM
module, and an `index.html`. That origin has no user-controlled input, no
templating, and no dynamic responses. Its injection surface is as close to zero
as a web origin gets, and it stays that way as the API grows.

**3. It is the decision this repo has already made for development.**
`app/vite.config.ts` pins a dedicated port with a comment that is worth quoting,
because it is the same argument:

> *SECURITY, not preference. localStorage is per-ORIGIN … On Vite's default port
> this origin is shared with every other project started with `npm run dev` — a
> real `localhost:5173` was found holding another app's auth token and JWT
> alongside a Keyward vault … A dedicated port gives the vault an origin of its
> own.*

Having concluded in dev that the vault must not share an origin with unrelated
code, shipping it on a shared origin in production would contradict a decision
already made, documented, and prompted by a real observation.

**4. The cost is close to zero.** The split needs CORS. The sync server already
sends `Access-Control-Allow-Origin: *`, so it works today with no server change
(see [CORS](#cors) for why that wildcard is not the problem it looks like). The
rest of the cost is one extra DNS record and one extra certificate, both
automated.

### What this does *not* buy you

Worth stating plainly so the control is not over-trusted:

- **It does not protect the API from a compromised vault origin.** The device
  token lives in that same `localStorage`. An XSS on the vault origin reads the
  token and can then call the API legitimately from anywhere. Origin separation
  shrinks the blast radius *into* the vault, not *out of* it.
- **It does not make CORS a security control here.** See below.
- **It does not address §10 itself.** Plaintext key material in `localStorage`
  remains the underlying issue; moving to non-extractable `CryptoKey` handles in
  IndexedDB is the actual fix, and it is an app-level change this directory
  cannot make. Origin separation reduces what can reach those secrets. It does
  not harden the secrets.

### CORS

The sync server sends `Access-Control-Allow-Origin: *` on every response
(`crates/sync-server/src/main.rs`, noted in `known-limitations.md`). Two things
follow, and they point in opposite directions:

- **It is not a CSRF hole.** Authentication is a bearer **header**, not a cookie.
  There is no ambient credential a hostile origin can ride, and a cross-origin
  page cannot read a response it has no token for. A wildcard here grants an
  attacker nothing they did not already have.
- **It is still worth revisiting**, because it is broader than the deployment
  needs and it invites the assumption that CORS is doing work it is not.

**Recommendation: keep the wildcard for now, and do not "fix" it reflexively.**
Narrowing `Access-Control-Allow-Origin` to the managed vault host would break the
project's own self-hosting story in a way that is hard to diagnose: a user
running their own vault build, or a desktop shell, against your relay would start
failing CORS preflight with no server-side error. If you do narrow it, make it an
explicit allowlist (config-driven), not a single hardcoded host — and note it is
a `crates/sync-server` change, out of scope for this directory.

## CONNECT-SRC

`connect-src` is the one CSP directive that is deployment-specific, so it is
substituted at container start from `KEYWARD_CSP_CONNECT_SRC` (see
`k8s/web-deployment.yaml`). The shipped default is deliberately permissive:

```
'self' https: http://localhost:* http://127.0.0.1:* https://api.pwnedpasswords.com
```

**Why so wide?** The sync server address is **typed by the user**
(`app/src/components/SyncDialog.vue`); pointing the vault at your own relay is a
core promise of the project. A single hardcoded API host in `connect-src` breaks
every self-hoster who does that, and the only symptom is a console CSP error.
`http://localhost:*` is there because `app/src/lib/sync.ts` explicitly permits
loopback over plain HTTP (and *only* loopback — it refuses plain HTTP to any
other host, so the device token cannot go out in the clear).
`https://api.pwnedpasswords.com` is the Watchtower breach check
(`app/src/lib/passbook.ts`) and is easy to omit by accident.

**If you run a closed, single-tenant deployment, tighten this.** It is the
single highest-value hardening step available to you:

```yaml
- name: KEYWARD_CSP_CONNECT_SRC
  value: "'self' https://sync.keyward.example https://api.pwnedpasswords.com"
```

With `https:` present, an XSS on the vault origin can POST the Secret Key to any
TLS endpoint it likes; with an allowlist, it cannot. Keep
`api.pwnedpasswords.com` either way or breach-checking silently fails.

## Prerequisites

- A Kubernetes cluster (v1.27+; manifests use `apps/v1` + `networking.k8s.io/v1`).
- An **ingress controller** — these manifests assume
  [ingress-nginx](https://kubernetes.github.io/ingress-nginx/) (`ingressClassName: nginx`).
- [**cert-manager**](https://cert-manager.io/) with a `ClusterIssuer` for TLS.
  The Ingress references `cert-manager.io/cluster-issuer: letsencrypt-prod` —
  create that issuer (or change the annotation to your issuer's name).
- A default (or explicitly set) **StorageClass** (for the bundled Postgres PVC).
- **PostgreSQL** — either the bundled in-cluster StatefulSet (`k8s/postgres.yaml`)
  or a managed DB you point `KEYWARD_SYNC_PG` at (preferred for production).
- The **`keyward-sync-secrets`** Secret (see [Secrets](#secrets) below).
- **Two** DNS records pointing at the ingress controller's external address — one
  for the sync API host, one for the vault host. Keep them distinct; see
  [Which origin serves the vault](#which-origin-serves-the-vault).

## Build & push the image

Build from the **repository root** (the Cargo workspace is the build context):

```bash
# From the repo root:
docker build -f deploy/Dockerfile -t ghcr.io/klarlabs-studio/keyward-sync-server:1.42.0 .
docker push ghcr.io/klarlabs-studio/keyward-sync-server:1.42.0
```

The image is **server only** (no demo seeder, no CLI), runs as a non-root user
(`uid 10001`), stores data under `/data` (declared a `VOLUME`), listens on
`0.0.0.0:8787`, and ships a `HEALTHCHECK` that curls `/healthz`.

### The web vault image

Also built from the **repository root** — not from `app/`. The build needs both
trees, because the SPA's crypto core is compiled from `crates/passbook-wasm`:

```bash
# From the repo root:
docker build -f deploy/Dockerfile.web -t ghcr.io/klarlabs-studio/keyward-web:2.0.0 .
docker push ghcr.io/klarlabs-studio/keyward-web:2.0.0
```

The image runs **nginx-unprivileged as uid 101**, listens on **8080** (it cannot
bind a privileged port, and the pod drops `NET_BIND_SERVICE`), serves the built
SPA from `/usr/share/nginx/html`, and answers `/healthz` for probes.

**Build order inside the Dockerfile is load-bearing.** `npm run build:wasm` must
run *before* `npm run build`, because `npm run build` starts with `vue-tsc
--noEmit` and `app/src/lib/passbook.ts` / `sharing.ts` import
`../wasm/pkg/passbook_wasm.js` — a module wasm-pack **generates** and that is not
committed. In the other order, type-checking fails with `TS2307: Cannot find
module`. The ordering is encoded in `deploy/Dockerfile.web` and in
`.github/workflows/ci.yml`; if you change one, change both.

**Apple Silicon.** Unlike `deploy/Dockerfile`, this image builds fine on arm64
*natively* — useful for the smoke test below. Building it
`--platform linux/amd64` from an Apple Silicon workstation still compiles Rust
under QEMU and hits the same `qemu: uncaught target signal 11` rustc segfault
documented in `Dockerfile.static`. Let the amd64 runner in
`.github/workflows/release.yml` build the released image.

### Releasing both images

`.github/workflows/release.yml` builds and pushes **both** on a `v*` tag:

```bash
git tag -a v2.0.0 -m 'Keyward 2.0.0' && git push origin v2.0.0
```

A shared `version` job asserts the tag matches `Cargo.toml` **and**
`app/package.json` before either image builds, so a release cannot publish a
relay and a vault bundle that disagree about their own version. Both images take
their tag from the git tag; keep the two `images[].newTag` values in
`k8s/kustomization.yaml` in step.

**Digest-pinned base images.** For reproducible, tamper-resistant builds the base
images are pinned by digest (`image:tag@sha256:…`) in
[`Dockerfile`](Dockerfile) (`rust:1.90-bookworm`, `debian:bookworm-slim`), in
[`Dockerfile.web`](Dockerfile.web) (`node:22-bookworm`,
`nginxinc/nginx-unprivileged:1.27-alpine`), and in
[`k8s/postgres.yaml`](k8s/postgres.yaml) (`postgres:16.4-alpine`). The human tag
is kept before the `@` for readability. To re-pin when upgrading a base image,
resolve the new digest without a full pull and paste it in:

```bash
docker buildx imagetools inspect <image>:<tag> --format '{{.Manifest.Digest}}'
# then update the FROM line / image: field to <image>:<tag>@sha256:<digest>
```

## Configure the hosts & TLS

There are **two** Ingresses and each needs its own hostname:

| File | Replace | With | Cert secret |
|---|---|---|---|
| [`k8s/ingress.yaml`](k8s/ingress.yaml) | `sync.keyward.example` (**both** occurrences) | your API hostname | `keyward-sync-tls` |
| [`k8s/web-ingress.yaml`](k8s/web-ingress.yaml) | `app.keyward.example` (**both** occurrences) | your vault hostname | `keyward-web-tls` |

Set the `cert-manager.io/cluster-issuer` annotation on both to your issuer;
cert-manager provisions each cert automatically.

> **Keep the two hostnames distinct.** Pointing both at one host collapses the
> origin separation described in
> [Which origin serves the vault](#which-origin-serves-the-vault) and silently
> discards the security property the split exists for. Nothing will error — it
> will just work, less safely.

Pin the image tags in [`k8s/kustomization.yaml`](k8s/kustomization.yaml)
(`images[].newTag`, one entry per image).

## Security headers (web vault)

`deploy/nginx/default.conf.template` sets these on **every** response, including
errors (each `add_header` carries `always`; without it nginx omits headers on a
404, so an attacker who can provoke one gets a response with no CSP):

| Header | Value | Why |
|---|---|---|
| `Content-Security-Policy` | see below | The main event. |
| `X-Content-Type-Options` | `nosniff` | The app serves `.wasm`; sniffing is how "static asset" becomes "executed as something else". |
| `X-Frame-Options` | `DENY` | Legacy duplicate of `frame-ancestors`. |
| `Referrer-Policy` | `no-referrer` | Neither the sync server nor pwnedpasswords needs to learn which page called it, and nothing here needs a `Referer`. |
| `Cross-Origin-Opener-Policy` | `same-origin` | A page the vault navigates to (e.g. Stripe Checkout) cannot reach back via `window.opener`. |
| `Cross-Origin-Resource-Policy` | `same-origin` | Refuse to be loaded as another origin's subresource. |
| `Permissions-Policy` | camera/mic/geo/USB/etc. off | An XSS cannot reach for hardware the vault never uses. |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | `preload` deliberately omitted — it is effectively permanent and would bind subdomains this repo does not own. |

The CSP, which was chosen against the **actual build output** rather than from a
template:

```
default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self';
img-src 'self' data:; font-src 'self'; connect-src ${KEYWARD_CSP_CONNECT_SRC};
manifest-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none';
frame-ancestors 'none'; object-src 'none'
```

The parts that are not obvious:

- **`'wasm-unsafe-eval'` is required, and is *not* `'unsafe-eval'`.** Chrome
  refuses to compile *any* WebAssembly unless `script-src` carries one of the
  two, and the app's whole crypto core — Argon2, XChaCha20-Poly1305, X25519 — is
  a WASM module. Without it the vault cannot decrypt anything.
  `'wasm-unsafe-eval'` is the narrow token: WASM compilation only, still no
  `eval()` / `new Function()`. Do not "simplify" it to `'unsafe-eval'`; that
  hands an XSS a string-to-code primitive on the origin holding the Secret Key.
- **No `'unsafe-inline'` anywhere, and no nonces needed.** The built
  `index.html` contains no inline `<script>` and no inline `<style>` — Vite's
  modulepreload polyfill (which *would* be injected inline) is absent because the
  app has one entry chunk and no dynamic imports. If the app ever gains
  code-splitting, that inline shim reappears and this CSP will block it; the
  symptom is a blank page and a CSP violation on an inline script.
- **`style-src 'self'` holds despite Vue's `:style` bindings and static
  `style="…"` attributes in templates**, because Vue applies them through the
  CSSOM (`element.style`), which CSP does not govern. Verified in a real browser,
  not assumed.
- **`base-uri 'none'` matters more than usual here.** The app is built with Vite
  `base: './'`, so every asset reference is relative — exactly the situation an
  injected `<base>` tag turns into "load my bundle from the attacker's host".
- **`upgrade-insecure-requests` is deliberately absent.** It would rewrite
  `http://localhost:8787` to `https://`, breaking the loopback self-hosting path
  that `app/src/lib/sync.ts` explicitly supports. It looks like free hardening
  and quietly breaks a documented workflow.

Caching is set by a `map` rather than per-location `add_header`, because nginx
drops *every* inherited `add_header` in any block that declares one — the obvious
implementation would have silently removed the CSP from exactly the responses
that need it. `index.html` is `no-cache, must-revalidate`; content-hashed
`/assets/*` are `immutable, max-age=31536000`. The `no-cache` on the entry
document is what lets a security fix reach clients: it is the file that pins
which JS bundle a browser runs.

There is **no SPA fallback** (`try_files … /index.html`), deliberately. The app
has no client-side router (`vue-router` is not a dependency), and with
`base: './'` a fallback would serve `index.html` for `/foo/bar` whose relative
asset URLs then resolve to `/foo/assets/…` and 404 — producing an HTTP 200 blank
page instead of an honest 404.

## Verifying the image locally

Static nginx builds natively on arm64, so this smoke test runs on an Apple
Silicon workstation (the Rust *server* image does not — see above). Run the
container under the **same** constraints the pod applies, or the test proves
nothing about production:

```bash
docker build -f deploy/Dockerfile.web -t keyward-web:test .

docker run --rm -d --name keyward-web-test \
  --read-only --cap-drop ALL --user 101:101 \
  --tmpfs /etc/nginx/conf.d:rw,mode=0777 \
  --tmpfs /var/cache/nginx:rw,mode=0777 \
  --tmpfs /tmp:rw,mode=0777 \
  -p 18080:8080 keyward-web:test

curl -sS -D- -o /dev/null http://127.0.0.1:18080/          # headers + Cache-Control: no-cache
curl -sS -D- -o /dev/null http://127.0.0.1:18080/assets/*.wasm  # expect Content-Type: application/wasm
curl -sS http://127.0.0.1:18080/healthz                    # expect: ok
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18080/nope   # expect 404, not 200
```

**Check the logs, not just the exit code.** The writable-mount requirement has a
nasty failure mode, found exactly this way:

```
20-envsubst-on-templates.sh: ERROR: /etc/nginx/templates exists, but /etc/nginx/conf.d is not writable
```

The entrypoint prints that and **carries on**. nginx starts, reports `start
worker processes`, and the container shows as `Up` — but `conf.d` is empty, so
there is no server block at all and every request gets a TCP reset. Nothing is
served, so no header is "missing" to alert you. This is why
`k8s/web-deployment.yaml` sets `fsGroup: 101` (so the kubelet makes the emptyDir
volumes writable by the container's group) and why the readiness probe on
`/healthz` is not optional.

Finally, load `http://127.0.0.1:18080/` in a browser and create a throwaway
vault. That is the only test that exercises the whole CSP: creating a vault runs
Argon2 in the WASM module, which is what proves `'wasm-unsafe-eval'` is present
and sufficient. The DevTools console should show **no CSP violations**.

## Secrets

The Deployment reads the Postgres URL and (optional) Stripe webhook secret from a
Secret named `keyward-sync-secrets`. **No Secret manifest is committed** (that would
put credentials in version control) — create it out-of-band from real values:

```bash
kubectl -n keyward create secret generic keyward-sync-secrets \
  --from-literal=postgres-password="$PG_PASSWORD" \
  --from-literal=postgres-url="$PG_URL" \
  --from-literal=stripe-webhook-secret="$STRIPE_WEBHOOK_SECRET"
```

Required keys:

| Key | Value |
|---|---|
| `postgres-password` | The Postgres password (must match the one inside `postgres-url`). |
| `postgres-url` | The libpq URL, e.g. host `keyward-postgres`, port `5432`, db `keyward`. |
| `stripe-webhook-secret` | Optional; the `whsec_…` signing secret. Omit to leave billing disabled. |

In production, manage this with sealed-secrets / external-secrets rather than by hand.

## Deploy

With Kustomize (recommended — applies the whole set in order):

```bash
kubectl apply -k deploy/k8s
```

Or apply the raw manifests directly:

```bash
kubectl apply -f deploy/k8s/
```

Verify:

```bash
kubectl -n keyward rollout status deploy/keyward-sync-server
kubectl -n keyward get pods,svc,ingress,pvc
# cert-manager progress:
kubectl -n keyward get certificate,order,challenge
```

Once the certificates are `Ready`:

```bash
curl https://<your-sync-host>/healthz   # => {"status":"ok"}
curl -I https://<your-vault-host>/      # => 200, text/html, plus the CSP header
```

Then open `https://<your-vault-host>/` in a browser — that is the product. Point
its **Sync settings** at `https://<your-sync-host>` to connect the two.

## Configuration (environment)

Set on the container in `k8s/deployment.yaml`:

| Env var | Default (image) | Meaning |
|---|---|---|
| `KEYWARD_SYNC_ADDR` | `0.0.0.0:8787` | Listen address (plain HTTP, behind the ingress). |
| `KEYWARD_SYNC_PG` | from Secret | PostgreSQL URL → the scalable managed backend. Takes precedence over `KEYWARD_SYNC_DIR`. |
| `KEYWARD_SYNC_PG_POOL` | `8` | Postgres connection-pool size per replica. |
| `KEYWARD_STRIPE_WEBHOOK_SECRET` | from Secret (optional) | Stripe webhook signing secret. Unset ⇒ `POST /v1/billing/webhook` returns 503. |
| `KEYWARD_STRIPE_SECRET_KEY` | from Secret (optional) | Stripe API secret key, used server-side to create Checkout sessions. Never sent to clients. |
| `KEYWARD_STRIPE_PRICE_FAMILY` | optional | Stripe price id for the Family plan. Together with the secret key it enables `POST /v1/billing/checkout`; either missing ⇒ 503. |
| `KEYWARD_STRIPE_SUCCESS_URL` / `KEYWARD_STRIPE_CANCEL_URL` | example.com defaults | Where Stripe redirects after checkout completes / is cancelled. |
| `KEYWARD_SYNC_DIR` | unset here | File-backed store (single-node self-host path). Ignored when `KEYWARD_SYNC_PG` is set. |
| `KEYWARD_SYNC_TOKEN_TTL` | unset → no expiry | Device-token lifetime in seconds. Manifest sets `2592000` (30 days). `0`/unset ⇒ tokens never expire. |
| `KEYWARD_SYNC_RATELIMIT_PER_MIN` | `30` | Per-client-IP fixed-window rate limit for the abuse-prone endpoints (`POST /v1/register`, `POST /v1/groups/{id}/invites`). Over the limit ⇒ HTTP `429`. `0` disables. Closes the DoS item in ADR-0004's threat model. |
| `KEYWARD_SYNC_TRUST_PROXY` | unset (off) | Honour `X-Forwarded-For` when deriving the client IP for rate limiting. **Set this if and only if traffic reaches the pod through a proxy.** Behind an ingress every connection appears to come from the controller pod, so without it the per-IP limit becomes one global bucket any single client can exhaust for everyone. The header is caller-supplied, so on a directly-exposed server trusting it would let clients mint a fresh identity per request and bypass limiting entirely. The rightmost entry is used — a client may prepend anything, but the last element is appended by the nearest trusted proxy. |
| `KEYWARD_SYNC_TOKENS` | unset | Optional static `token:account,…` pre-seed (bootstrap/test only; the registry is authoritative). |

> The rate limiter is **in-memory and per-pod**. With multiple replicas each pod
> keeps its own counter, so the effective limit is roughly `replicas ×
> KEYWARD_SYNC_RATELIMIT_PER_MIN` — set the per-pod value with that in mind, or move
> to a shared limiter (Redis) if you need a precise global cap. It is keyed by the
> client IP as seen by the server — behind nginx-ingress that is typically the
> proxy's address unless you enable real-client-IP forwarding
> (`externalTrafficPolicy: Local` and/or nginx's `use-forwarded-headers`).

## Scaling

The **web vault** runs 2 replicas with a `minAvailable: 1` PDB and **no HPA**,
deliberately. It serves a handful of small, page-cached files with `sendfile()`;
it will saturate a network link long before it approaches a CPU target, so an
HPA scaling on CPU could never trigger. An HPA that can never fire is worse than
none — it reports `cpu: <unknown>/70%` and reads like working autoscaling. Its
resource limits are intentionally low (200m CPU / 64Mi): if this container ever
needs more, something is wrong and throttling is the right outcome. The two
replicas are for availability during rolling updates and node drains, not
throughput.

The API is **stateless** (all state is in Postgres), so it scales horizontally.
The Deployment runs `replicas: 2` with `RollingUpdate` (zero-downtime deploys), and
[`k8s/hpa.yaml`](k8s/hpa.yaml) autoscales 2→10 on CPU. The only stateful component
is Postgres — scale/HA that at the database layer (a managed DB or an operator).

A [`PodDisruptionBudget`](k8s/pdb.yaml) (`minAvailable: 1`) keeps at least one app
replica Ready through **voluntary** disruptions (node drains, cluster upgrades), so
`kubectl drain` never takes the whole service down at once. There is deliberately
**no PDB for the single-replica Postgres** — one would make its only pod
undrainable and block node drains; give Postgres real HA before budgeting it.

## Network hardening

[`k8s/networkpolicy.yaml`](k8s/networkpolicy.yaml) applies a **default-deny
ingress** posture for the `keyward` namespace plus the minimum explicit allows
(requires a NetworkPolicy-enforcing CNI such as Calico or Cilium; on other CNIs
the objects are inert but harmless):

- **default-deny-ingress** — every pod rejects inbound traffic unless another
  policy allows it. Egress is left permissive on purpose so DNS, cert-manager's
  ACME calls, and the app's outbound HTTPS to Stripe keep working; locking egress
  down is a **follow-up** (if you add an egress policy you must allow DNS to
  kube-dns on UDP+TCP 53, app→Postgres :5432, and app→internet :443).
- **allow-ingress-to-app** — app pods accept TCP `8787` from the ingress-controller
  namespace, a monitoring namespace (Prometheus `/metrics` scrape), and same-
  namespace scrapers.
- **allow-ingress-to-web** — web pods accept TCP `8080` from the ingress-controller
  namespace. **Required**: the default-deny selects every pod in the namespace and
  `allow-ingress-to-app` matches only the sync server, so without this rule the
  vault UI is unreachable — and the symptom is a 502/504 from the ingress while
  `kubectl get pods` shows `keyward-web` perfectly `Ready`, which is a confusing
  place to start debugging. Note port **8080**, not 8787. There is no monitoring
  rule because this image exposes no Prometheus endpoint.
- **allow-app-to-postgres** — Postgres accepts TCP `5432` **only** from the app
  pods; nothing else in the namespace can reach the database.

There is deliberately **no web→app rule**: the web pods never call the sync
server. The browser does, directly, from the user's machine.

**Per-cluster values to adjust** (namespaceSelector labels in
`allow-ingress-to-app`, matched on the auto-populated `kubernetes.io/metadata.name`
namespace label):

| Selector | Default value | Change to… |
|---|---|---|
| Ingress-controller namespace | `ingress-nginx` | wherever ingress-nginx runs (e.g. `kube-system`). |
| Monitoring namespace | `monitoring` | wherever Prometheus runs (kube-prometheus-stack default is `monitoring`). |

If you don't scrape from inside the `keyward` namespace, drop the same-namespace
`podSelector: {}` block from `allow-ingress-to-app`.

## Health & metrics

- `GET /healthz` → `200 {"status":"ok"}` — liveness (also the image `HEALTHCHECK`).
- `GET /readyz` → `200 {"status":"ok"}` — readiness.
- `GET /metrics` → Prometheus exposition (`keyward_requests_total`,
  `keyward_uptime_seconds`, `keyward_build_info{backend,version}`). Aggregate
  counters only (no PII). The pod carries `prometheus.io/scrape` annotations, and
  Prometheus scrapes the pod **directly** on 8787 — that path does not traverse
  the ingress.

  > **`/metrics` IS routed by the ingress unless you block it.** This line
  > previously claimed the opposite. It was wrong: `k8s/ingress.yaml` routes
  > `path: /` with `pathType: Prefix`, which matches every path, and a live
  > deployment served `/metrics` to the open internet with HTTP 200. It exposes
  > no secrets or PII, but it does publish the exact version and backend —
  > useful for matching known CVEs to a target — plus account, family and invite
  > totals.
  >
  > **The base manifests do not block it.** You have to, and you should verify
  > it from off-cluster rather than assume — that is how the original claim went
  > unchallenged. `k8s/examples/metrics-block-traefik.yaml` is a working Traefik
  > implementation: a dedicated `/metrics` Ingress with a deny middleware
  > (verified in production: 403 from the internet, API endpoints unaffected).
  > On ingress-nginx the equivalent is:
  >
  > ```yaml
  > nginx.ingress.kubernetes.io/server-snippet: |
  >   location /metrics { deny all; return 403; }
  > ```

All three are unauthenticated and **not** rate-limited so probes/scrapes are never
throttled.

## Backup & restore (PostgreSQL)

The database holds only **ciphertext** vault blobs, public keys, and hashed
tokens/invite codes — but it *is* your users' data, so store backups **encrypted**.
For real durability use a managed DB / operator with **point-in-time recovery**;
the baseline is a scheduled `pg_dump` via [`backup.sh`](backup.sh):

```bash
# Dump / restore against any reachable Postgres (PG_URL is your connection URL):
PG_URL='<your-postgres-url>' ./deploy/backup.sh backup ./backups
PG_URL='<your-postgres-url>' ./deploy/backup.sh restore ./backups/keyward-<stamp>.sql.gz

# ...or against the bundled in-cluster StatefulSet without exposing Postgres:
kubectl -n keyward exec -i statefulset/keyward-postgres -- \
  pg_dump -U keyward keyward | gzip > keyward-backup.sql.gz
```

Take a dump before upgrades. Losing the database means every account must
re-register and re-upload its (client-encrypted) vault.

## Uninstall

```bash
kubectl delete -k deploy/k8s
# The bundled Postgres StatefulSet's PVC is retained by default; delete it
# explicitly to remove the data:
kubectl -n keyward delete pvc -l app.kubernetes.io/name=keyward-postgres
```
