#!/bin/sh
# End-to-end demo on the authorized localhost fixture.
#
# Runs a web-blackbox plan, expands the web prompt library against a local
# threat model, executes the deterministic fixture evaluation (14 positive
# probes and 14 negative controls), and renders the report.
#
# Nothing leaves loopback. No Docker, no external target, no paid API.
#
# Usage: sh scripts/demo.sh [run-dir]
#        sh scripts/demo.sh runs/demo

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
RUN_DIR=${1:-"$ROOT/runs/demo"}

# Choose the fixture port before writing scope, plan or metadata so every
# artifact names the same target. If 8765 is busy, an ephemeral loopback port is
# used instead of silently evaluating a different target under the demo scope.
PORT=$(python3 - <<'PY'
import socket

for candidate in (8765, 0):
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind(("127.0.0.1", candidate))
        print(probe.getsockname()[1])
        probe.close()
        break
    except OSError:
        probe.close()
else:
    raise SystemExit("no loopback port available for the demo")
PY
)
TARGET="http://127.0.0.1:$PORT"

cd "$ROOT"
mkdir -p "$RUN_DIR/prompts" "$RUN_DIR/evidence" "$RUN_DIR/logs"

cat > "$RUN_DIR/scope.md" <<SCOPE
# Scope — localhost demo

- Authorization: this repository's local vulnerable fixture is the authorized target.
- In scope: $TARGET only (loopback).
- Accounts: seeded fixture accounts documented in tests/fixtures/vuln_app/SEEDED.md; no real accounts.
- Data: deterministic fake seed only.
- Out of scope: any non-loopback host, cloud metadata, denial of service, real personal data,
  destructive actions outside the fixture's own reset.
- Mode: blackbox, normal intensity. Budget: plan defaults, 120 seconds, one request at a time.
SCOPE

echo "target: $TARGET"

cat > "$RUN_DIR/threat-model.md" <<'THREAT'
# Threat model — localhost fixture

## Assets

- User account records (email, role, credits, reset token)
- Credit balance and AI usage quota
- Admin-only actions and the hidden cache purge
- Internal metadata endpoint reached by the server-side fetch
- Dashboard HTML cached for signed-in users
- LLM chat answer rendered to the user

## Trust boundaries

- Anonymous request to authenticated API
- One user to another user's objects
- User session to admin action
- Client-supplied URL to server-side fetch
- Stored profile text to rendered HTML
- Prompt content to model answer across tenants

## Invariants

- A caller may read or write only their own account unless the role is admin
- Role and credits are not client-assignable through a profile update
- A password-reset token is single-use
- AI quota and credit balance are enforced by the API, atomically
- User input is length, type and range validated before storage
- Untrusted text is encoded for its output context
- Redirect targets are local paths only
- Shared cache keys include the authenticated principal
- Server-side fetches allowlist loopback destinations and reject DNS aliases
- Model answers never cross a tenant boundary
THREAT

echo "== plan =="
uv run sak plan --suite web-blackbox --target "$TARGET" \
  --run-dir "$RUN_DIR" --allow-missing-requires

echo
echo "== prompt library =="
uv run sak prompts list --domain web --json > "$RUN_DIR/prompts.json"
for number in 01 02 03 04 05 06 07 08 09 10 11 12 13 14; do
  uv run sak prompts expand "VIBE-$number" \
    --threat-model "$RUN_DIR/threat-model.md" \
    --json > "$RUN_DIR/prompts/VIBE-$number.json"
done
echo "wrote $RUN_DIR/prompts.json and 14 expanded VIBE prompts"

echo
echo "== deterministic fixture evaluation =="
python3 eval/run_fixture.py \
  --run-dir "$RUN_DIR" \
  --run-id demo-web-blackbox \
  --port "$PORT" \
  --artifacts

echo
echo "== report =="
uv run sak report "$RUN_DIR"

echo
echo "demo complete: $RUN_DIR/REPORT.md"
