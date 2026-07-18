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
client ──HTTPS──▶ nginx-ingress (TLS via cert-manager) ──HTTP──▶ Service ──▶ Pod :8787 ──▶ PVC /data
```

## Prerequisites

- A Kubernetes cluster (v1.27+; manifests use `apps/v1` + `networking.k8s.io/v1`).
- An **ingress controller** — these manifests assume
  [ingress-nginx](https://kubernetes.github.io/ingress-nginx/) (`ingressClassName: nginx`).
- [**cert-manager**](https://cert-manager.io/) with a `ClusterIssuer` for TLS.
  The Ingress references `cert-manager.io/cluster-issuer: letsencrypt-prod` —
  create that issuer (or change the annotation to your issuer's name).
- A default (or explicitly set) **StorageClass** for the PVC.
- A DNS record pointing your host at the ingress controller's external address.

## Build & push the image

Build from the **repository root** (the Cargo workspace is the build context):

```bash
# From the repo root:
docker build -f deploy/Dockerfile -t ghcr.io/klarlabs/proctor-sync-server:1.30.0 .
docker push ghcr.io/klarlabs/proctor-sync-server:1.30.0
```

The image is **server only** (no demo seeder, no CLI), runs as a non-root user
(`uid 10001`), stores data under `/data` (declared a `VOLUME`), listens on
`0.0.0.0:8787`, and ships a `HEALTHCHECK` that curls `/healthz`.

## Configure the host & TLS

Edit [`k8s/ingress.yaml`](k8s/ingress.yaml) and replace **both** occurrences of
`sync.proctor.example` with your real hostname, and set the
`cert-manager.io/cluster-issuer` annotation to your issuer. cert-manager will
provision the cert into the `proctor-sync-tls` secret automatically.

Pin the image tag in [`k8s/kustomization.yaml`](k8s/kustomization.yaml)
(`images[].newTag`) or in [`k8s/deployment.yaml`](k8s/deployment.yaml).

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
| `PROCTOR_SYNC_DIR` | `/data` | Storage dir (file-backed stores). Mounted from the PVC. |
| `PROCTOR_SYNC_TOKEN_TTL` | unset → no expiry | Device-token lifetime in seconds. Manifest sets `2592000` (30 days). `0`/unset ⇒ tokens never expire. |
| `PROCTOR_SYNC_RATELIMIT_PER_MIN` | `30` | Per-client-IP fixed-window rate limit for the abuse-prone endpoints (`POST /v1/register`, `POST /v1/groups/{id}/invites`). Over the limit ⇒ HTTP `429`. `0` disables. Closes the DoS item in ADR-0004's threat model. |
| `PROCTOR_SYNC_TOKENS` | unset | Optional static `token:account,…` pre-seed (bootstrap/test only; the registry is authoritative). |

> The rate limiter is **in-memory and per-pod**. With the single replica this
> deployment mandates (see below) that is exactly one counter set. It is keyed by
> the client IP as seen by the server — behind nginx-ingress that is typically
> the proxy's address unless you enable real-client-IP forwarding
> (`externalTrafficPolicy: Local` and/or nginx's `use-forwarded-headers`). Tune
> `PROCTOR_SYNC_RATELIMIT_PER_MIN` accordingly if all traffic appears from one IP.

## Scaling constraints

The server persists to a **ReadWriteOnce** PVC, so **exactly one replica** may
mount it. The Deployment therefore uses `replicas: 1` and `strategy: Recreate`
(a rolling update would transiently run two pods, and the second cannot attach
the volume). Do **not** raise `replicas` without moving to a shared backing
store — that is out of scope here.

## Health endpoints

- `GET /healthz` → `200 {"status":"ok"}` — liveness (used by the liveness probe
  and the image `HEALTHCHECK`).
- `GET /readyz` → `200 {"status":"ok"}` — readiness (used by the readiness probe).

Both are unauthenticated and **not** rate-limited so probes are never throttled.

## Backup & restore of `/data`

All server state lives on the `proctor-sync-data` PVC (`/data`). Because the
contents are **ciphertext**, backups are safe to store on ordinary infrastructure
— but still protect availability and integrity.

**Preferred:** snapshot the PVC with your storage provider / a tool like Velero
(`VolumeSnapshot`), on a schedule.

**Manual tarball backup** (simple, provider-agnostic):

```bash
POD=$(kubectl -n proctor get pod -l app.kubernetes.io/name=proctor-sync-server -o name)
kubectl -n proctor exec "$POD" -- tar -C /data -czf - . > proctor-sync-$(date +%F).tgz
```

**Restore** into a fresh (empty) PVC — scale down first so nothing writes
concurrently:

```bash
kubectl -n proctor scale deploy/proctor-sync-server --replicas=0
# after the PVC is (re)created and a pod is scheduled but idle, or via a helper pod:
POD=$(kubectl -n proctor get pod -l app.kubernetes.io/name=proctor-sync-server -o name)
kubectl -n proctor exec -i "$POD" -- tar -C /data -xzf - < proctor-sync-2026-07-18.tgz
kubectl -n proctor scale deploy/proctor-sync-server --replicas=1
```

Snapshot before upgrades. Losing `/data` means every account must re-register and
re-upload its (client-encrypted) vault.

## Uninstall

```bash
kubectl delete -k deploy/k8s
# The PVC's underlying volume may be retained by its StorageClass reclaim policy;
# delete it explicitly if you want the data gone:
kubectl -n proctor delete pvc proctor-sync-data
```
