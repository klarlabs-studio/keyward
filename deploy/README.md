# Proctor sync server — managed-cloud deployment

This directory deploys the Proctor **zero-knowledge sync + family-sharing relay**
(`crates/sync-server`) to Kubernetes.

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
client ─HTTPS─▶ nginx-ingress (TLS via cert-manager) ─HTTP─▶ Service ─▶ Pods :8787 (N replicas) ─▶ PostgreSQL
```

The managed cloud uses the **PostgreSQL backend** (`PROCTOR_SYNC_PG`), so the API
is **stateless and horizontally scalable** — many replicas behind the Service, all
reading one database (`k8s/postgres.yaml` bundles a simple in-cluster Postgres; for
production point `PROCTOR_SYNC_PG` at a managed DB / operator instead). The
file-backed path (`PROCTOR_SYNC_DIR`) remains for single-node self-hosting.

## Prerequisites

- A Kubernetes cluster (v1.27+; manifests use `apps/v1` + `networking.k8s.io/v1`).
- An **ingress controller** — these manifests assume
  [ingress-nginx](https://kubernetes.github.io/ingress-nginx/) (`ingressClassName: nginx`).
- [**cert-manager**](https://cert-manager.io/) with a `ClusterIssuer` for TLS.
  The Ingress references `cert-manager.io/cluster-issuer: letsencrypt-prod` —
  create that issuer (or change the annotation to your issuer's name).
- A default (or explicitly set) **StorageClass** (for the bundled Postgres PVC).
- **PostgreSQL** — either the bundled in-cluster StatefulSet (`k8s/postgres.yaml`)
  or a managed DB you point `PROCTOR_SYNC_PG` at (preferred for production).
- The **`proctor-sync-secrets`** Secret (see [Secrets](#secrets) below).
- A DNS record pointing your host at the ingress controller's external address.

## Build & push the image

Build from the **repository root** (the Cargo workspace is the build context):

```bash
# From the repo root:
docker build -f deploy/Dockerfile -t ghcr.io/klarlabs-studio/proctor-sync-server:1.41.0 .
docker push ghcr.io/klarlabs-studio/proctor-sync-server:1.41.0
```

The image is **server only** (no demo seeder, no CLI), runs as a non-root user
(`uid 10001`), stores data under `/data` (declared a `VOLUME`), listens on
`0.0.0.0:8787`, and ships a `HEALTHCHECK` that curls `/healthz`.

**Digest-pinned base images.** For reproducible, tamper-resistant builds the base
images are pinned by digest (`image:tag@sha256:…`) in
[`Dockerfile`](Dockerfile) (`rust:1.90-bookworm`, `debian:bookworm-slim`) and in
[`k8s/postgres.yaml`](k8s/postgres.yaml) (`postgres:16.4-alpine`). The human tag
is kept before the `@` for readability. To re-pin when upgrading a base image,
resolve the new digest without a full pull and paste it in:

```bash
docker buildx imagetools inspect <image>:<tag> --format '{{.Manifest.Digest}}'
# then update the FROM line / image: field to <image>:<tag>@sha256:<digest>
```

## Configure the host & TLS

Edit [`k8s/ingress.yaml`](k8s/ingress.yaml) and replace **both** occurrences of
`sync.proctor.example` with your real hostname, and set the
`cert-manager.io/cluster-issuer` annotation to your issuer. cert-manager will
provision the cert into the `proctor-sync-tls` secret automatically.

Pin the image tag in [`k8s/kustomization.yaml`](k8s/kustomization.yaml)
(`images[].newTag`) or in [`k8s/deployment.yaml`](k8s/deployment.yaml).

## Secrets

The Deployment reads the Postgres URL and (optional) Stripe webhook secret from a
Secret named `proctor-sync-secrets`. **No Secret manifest is committed** (that would
put credentials in version control) — create it out-of-band from real values:

```bash
kubectl -n proctor create secret generic proctor-sync-secrets \
  --from-literal=postgres-password="$PG_PASSWORD" \
  --from-literal=postgres-url="$PG_URL" \
  --from-literal=stripe-webhook-secret="$STRIPE_WEBHOOK_SECRET"
```

Required keys:

| Key | Value |
|---|---|
| `postgres-password` | The Postgres password (must match the one inside `postgres-url`). |
| `postgres-url` | The libpq URL, e.g. host `proctor-postgres`, port `5432`, db `proctor`. |
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
kubectl -n proctor rollout status deploy/proctor-sync-server
kubectl -n proctor get pods,svc,ingress,pvc
# cert-manager progress:
kubectl -n proctor get certificate,order,challenge
```

Once the certificate is `Ready`, hit `https://<your-host>/healthz` — it should
return `{"status":"ok"}`.

## Configuration (environment)

Set on the container in `k8s/deployment.yaml`:

| Env var | Default (image) | Meaning |
|---|---|---|
| `PROCTOR_SYNC_ADDR` | `0.0.0.0:8787` | Listen address (plain HTTP, behind the ingress). |
| `PROCTOR_SYNC_PG` | from Secret | PostgreSQL URL → the scalable managed backend. Takes precedence over `PROCTOR_SYNC_DIR`. |
| `PROCTOR_SYNC_PG_POOL` | `8` | Postgres connection-pool size per replica. |
| `PROCTOR_STRIPE_WEBHOOK_SECRET` | from Secret (optional) | Stripe webhook signing secret. Unset ⇒ `POST /v1/billing/webhook` returns 503. |
| `PROCTOR_STRIPE_SECRET_KEY` | from Secret (optional) | Stripe API secret key, used server-side to create Checkout sessions. Never sent to clients. |
| `PROCTOR_STRIPE_PRICE_FAMILY` | optional | Stripe price id for the Family plan. Together with the secret key it enables `POST /v1/billing/checkout`; either missing ⇒ 503. |
| `PROCTOR_STRIPE_SUCCESS_URL` / `PROCTOR_STRIPE_CANCEL_URL` | example.com defaults | Where Stripe redirects after checkout completes / is cancelled. |
| `PROCTOR_SYNC_DIR` | unset here | File-backed store (single-node self-host path). Ignored when `PROCTOR_SYNC_PG` is set. |
| `PROCTOR_SYNC_TOKEN_TTL` | unset → no expiry | Device-token lifetime in seconds. Manifest sets `2592000` (30 days). `0`/unset ⇒ tokens never expire. |
| `PROCTOR_SYNC_RATELIMIT_PER_MIN` | `30` | Per-client-IP fixed-window rate limit for the abuse-prone endpoints (`POST /v1/register`, `POST /v1/groups/{id}/invites`). Over the limit ⇒ HTTP `429`. `0` disables. Closes the DoS item in ADR-0004's threat model. |
| `PROCTOR_SYNC_TOKENS` | unset | Optional static `token:account,…` pre-seed (bootstrap/test only; the registry is authoritative). |

> The rate limiter is **in-memory and per-pod**. With multiple replicas each pod
> keeps its own counter, so the effective limit is roughly `replicas ×
> PROCTOR_SYNC_RATELIMIT_PER_MIN` — set the per-pod value with that in mind, or move
> to a shared limiter (Redis) if you need a precise global cap. It is keyed by the
> client IP as seen by the server — behind nginx-ingress that is typically the
> proxy's address unless you enable real-client-IP forwarding
> (`externalTrafficPolicy: Local` and/or nginx's `use-forwarded-headers`).

## Scaling

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
ingress** posture for the `proctor` namespace plus the minimum explicit allows
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
- **allow-app-to-postgres** — Postgres accepts TCP `5432` **only** from the app
  pods; nothing else in the namespace can reach the database.

**Per-cluster values to adjust** (namespaceSelector labels in
`allow-ingress-to-app`, matched on the auto-populated `kubernetes.io/metadata.name`
namespace label):

| Selector | Default value | Change to… |
|---|---|---|
| Ingress-controller namespace | `ingress-nginx` | wherever ingress-nginx runs (e.g. `kube-system`). |
| Monitoring namespace | `monitoring` | wherever Prometheus runs (kube-prometheus-stack default is `monitoring`). |

If you don't scrape from inside the `proctor` namespace, drop the same-namespace
`podSelector: {}` block from `allow-ingress-to-app`.

## Health & metrics

- `GET /healthz` → `200 {"status":"ok"}` — liveness (also the image `HEALTHCHECK`).
- `GET /readyz` → `200 {"status":"ok"}` — readiness.
- `GET /metrics` → Prometheus exposition (`proctor_requests_total`,
  `proctor_uptime_seconds`, `proctor_build_info{backend,version}`). Aggregate
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
  > `overlays/klarlabs/metrics-block.yaml` blocks it for Traefik via a dedicated
  > `/metrics` Ingress with a deny middleware (verified: 403 from the internet,
  > API endpoints unaffected). On ingress-nginx the equivalent is:
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
PG_URL='<your-postgres-url>' ./deploy/backup.sh restore ./backups/proctor-<stamp>.sql.gz

# ...or against the bundled in-cluster StatefulSet without exposing Postgres:
kubectl -n proctor exec -i statefulset/proctor-postgres -- \
  pg_dump -U proctor proctor | gzip > proctor-backup.sql.gz
```

Take a dump before upgrades. Losing the database means every account must
re-register and re-upload its (client-encrypted) vault.

## Uninstall

```bash
kubectl delete -k deploy/k8s
# The bundled Postgres StatefulSet's PVC is retained by default; delete it
# explicitly to remove the data:
kubectl -n proctor delete pvc -l app.kubernetes.io/name=proctor-postgres
```
