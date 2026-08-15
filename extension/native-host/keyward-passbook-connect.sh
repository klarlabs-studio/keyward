#!/usr/bin/env bash
#
# Keyward Passbook — native-messaging host (desktop-app session)
# ==============================================================
#
# Chrome launches this script (the `path` in the native-host manifest) and
# speaks the native-messaging protocol over stdin/stdout. It hands stdio to
# `passbook connect`, which relays length-prefixed frames to the agent socket
# the running Keyward desktop app owns.
#
# This is the production path (issue #13, ADR-0007), and it replaces
# keyward-passbook-bridge.sh for the distributed extension.
#
# WHY THIS EXISTS
# ---------------------------------------------------------------------------
# The older wrapper unlocked the vault *in the host process* by reading the
# master password from a file on disk (KEYWARD_PASSBOOK_MASTER_FILE). Its own
# comment called that prototype-only, and #13 named it the weakest link across
# all three surfaces — web, desktop and extension.
#
# Nothing here holds a secret. There is no vault path, no master file and no
# secret key, because this process never opens a vault: the desktop app holds
# the unlocked session and decides, per request, whether it is unlocked. Lock
# the app and the next `get` is refused mid-connection.
#
# The relay does not parse the JSON either, so a protocol change needs no
# change to this script.
#
# REQUIREMENTS
#   - the Keyward desktop app running (it binds the agent socket at startup,
#     locked; binding before any unlock is inert rather than a leak)
#   - a `passbook` binary on PATH, or a release build in the repo's target/
#
# Chrome invokes the host with the calling extension's origin as $1, e.g.
# `chrome-extension://<id>/`. Chrome already enforces `allowed_origins` from the
# manifest, so it is ignored here.

set -euo pipefail

# Chrome passes the caller origin as $1 — intentionally unused.
: "${1:-}"

# --- Locate the passbook binary ---------------------------------------------
# Prefer a `passbook` on PATH; otherwise fall back to a release build sitting in
# the repo's target/ directory relative to this script.
if command -v passbook >/dev/null 2>&1; then
  PASSBOOK_BIN="$(command -v passbook)"
else
  SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
  PASSBOOK_BIN="${SCRIPT_DIR}/../../target/release/passbook"
fi

# Hand stdio to the relay. `exec` replaces this shell so Chrome talks directly
# to the binary (no extra process in the pipe).
exec "${PASSBOOK_BIN}" connect
