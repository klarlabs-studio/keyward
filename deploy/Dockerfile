# syntax=docker/dockerfile:1
#
# Production image for the Keyward zero-knowledge sync + family-sharing relay.
# SERVER ONLY — no demo seeder, no passbook CLI. Managed-cloud target: this runs
# plain HTTP behind an ingress that terminates TLS (see deploy/README.md).
#
# Build context is the repository ROOT (the Cargo workspace), e.g.:
#   docker build -f deploy/Dockerfile -t ghcr.io/klarlabs-studio/keyward-sync-server:1.30.0 .

# ---- build stage ---------------------------------------------------------
# Pinned to the workspace's rust-version (1.90) on Debian bookworm so the
# runtime glibc matches the debian:bookworm-slim base below.
FROM rust:1.90-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f AS build
WORKDIR /src
COPY . .
# LTO release build (profile.release in the workspace Cargo.toml). Server only.
RUN cargo build --release -p keyward-sync-server \
 && strip target/release/keyward-sync-server

# ---- runtime stage -------------------------------------------------------
# debian:bookworm-slim (not distroless) so a HEALTHCHECK can curl /healthz.
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

# curl is only needed for the container HEALTHCHECK; ca-certificates is harmless
# and future-proofs any outbound TLS. Kept minimal.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# Non-root runtime user. The data dir is created and owned by it up front so the
# server can write even without an fsGroup (k8s sets fsGroup too; both work).
RUN useradd --system --uid 10001 --user-group --home-dir /data --shell /usr/sbin/nologin app \
 && mkdir -p /data \
 && chown -R app:app /data

COPY --from=build /src/target/release/keyward-sync-server /usr/local/bin/keyward-sync-server

# Sensible in-container defaults. The server binds all interfaces because TLS is
# terminated upstream by the ingress; it is never exposed directly.
ENV KEYWARD_SYNC_ADDR=0.0.0.0:8787 \
    KEYWARD_SYNC_DIR=/data

USER app
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8787

# Liveness from the container runtime's point of view (k8s uses its own probes).
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8787/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/keyward-sync-server"]
