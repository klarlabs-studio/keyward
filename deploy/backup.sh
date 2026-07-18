#!/usr/bin/env bash
# Back up / restore the Proctor Postgres database.
#
# The dump holds ONLY ciphertext vault blobs, X25519 public keys, and hashed
# tokens/invite codes — never plaintext, master passwords, or Secret Keys (the
# zero-knowledge property). It is still your users' data: store backups ENCRYPTED
# and access-controlled. For real durability use a managed DB / operator with
# point-in-time recovery; this script is the simple baseline.
#
# Usage (PG_URL is your Postgres connection URL — keep it out of shell history):
#   PG_URL=<your-postgres-url> ./deploy/backup.sh backup [outdir]
#   PG_URL=<your-postgres-url> ./deploy/backup.sh restore file.sql.gz
#
# Against the in-cluster StatefulSet without exposing Postgres:
#   kubectl -n proctor exec -i statefulset/proctor-postgres -- \
#     pg_dump -U proctor proctor | gzip > proctor-backup.sql.gz
set -euo pipefail

cmd="${1:-backup}"
: "${PG_URL:?set PG_URL to the Postgres connection string}"

case "$cmd" in
  backup)
    outdir="${2:-.}"
    mkdir -p "$outdir"
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    out="$outdir/proctor-$stamp.sql.gz"
    pg_dump "$PG_URL" | gzip >"$out"
    echo "wrote $out"
    ;;
  restore)
    file="${2:?usage: restore <backup-file.sql.gz>}"
    gunzip -c "$file" | psql "$PG_URL"
    echo "restored $file"
    ;;
  *)
    echo "usage: $0 backup [outdir] | restore <file.sql.gz>" >&2
    exit 2
    ;;
esac
