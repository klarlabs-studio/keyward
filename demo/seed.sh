#!/usr/bin/env bash
# Seed the demo: build a REAL 2SKD-sealed vault with the passbook CLI, register a
# demo account on the sync server, and upload the sealed blob. The demo data lives
# only here — the production app carries none. Credentials are written to
# /out/credentials.txt (a bind mount) for the user to copy into the web vault's
# "Link this device" flow.
set -euo pipefail

SYNC_URL="${SYNC_URL:-http://sync:8787}"
MASTER="correct horse battery staple"

export PROCTOR_PASSBOOK=/tmp/vault.json
export PROCTOR_PASSBOOK_MASTER="$MASTER"
export PROCTOR_PASSBOOK_SECRETKEY_FILE=/tmp/secret.key

echo "seed: building the demo vault…"
passbook init >/dev/null
# A realistic spread of item types (passwords via '-' are generated).
passbook add-login gh    "GitHub"        "octocat@example.com"        - github.com JBSWY3DPEHPK3PXP >/dev/null
passbook add-login bank  "Ridgeline Bank" "demo.user"                 - ridgelinebank.example >/dev/null
passbook add-login mail  "Fastmail"      "demo@example.com"           - fastmail.example >/dev/null
passbook add-login shop  "Marketplace"   "demo@example.com"           - shop.example >/dev/null

SECRET_KEY="$(cat /tmp/secret.key)"

echo "seed: waiting for the sync server…"
for _ in $(seq 1 60); do
  curl -fsS -X POST "$SYNC_URL/v1/register" -o /tmp/reg.json -d '{"label":"Demo device"}' && break
  sleep 1
done

TOKEN="$(sed -n 's/.*"device_token":"\([^"]*\)".*/\1/p' /tmp/reg.json)"
ACCOUNT="$(sed -n 's/.*"account_id":"\([^"]*\)".*/\1/p' /tmp/reg.json)"

echo "seed: uploading the sealed vault…"
curl -fsS -X PUT "$SYNC_URL/v1/vault" \
  -H "Authorization: Bearer $TOKEN" \
  --data-binary @/tmp/vault.json -o /dev/null

mkdir -p /out
cat > /out/credentials.txt <<EOF
Proctor Passbook — demo credentials
===================================
Open the web vault:   http://localhost:8080

Then choose  Cloud sync ▸ Link this device  and enter:
  Server URL:    http://localhost:8787
  Device token:  $TOKEN

Unlock with:
  Master password:  $MASTER
  Secret Key:       $SECRET_KEY

(account id: $ACCOUNT — the server only ever stores ciphertext.)
EOF

echo "seed: done. Credentials:"
cat /out/credentials.txt
