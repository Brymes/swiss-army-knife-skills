#!/bin/sh
# vuln-bank harness: start the pinned upstream lab on loopback, wait for health,
# write scope/threat-model evidence, plan web-blackbox, run Nuclei and Playwright,
# import candidate findings and render a report.
#
# Dry run is the default: no Docker, no network, no browser. Live mode needs
# --execute and a checkout at the pinned commit (see clone.sh).
set -eu

TARGET_NAME="vuln-bank"
UPSTREAM_URL="https://github.com/Commando-X/vuln-bank"
PINNED_COMMIT="41c5b056f9ae8a8b15c77ea79f1419356b321634"
UPSTREAM_LICENSE="MIT"
DEFAULT_TARGET="http://127.0.0.1:5000"
DEFAULT_WEB_PORT="5000"
DEFAULT_HTTP_PORT="8080"
DEFAULT_TIMEOUT="180"
REQUEST_BUDGET="500"
TIME_BUDGET="900"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
UPSTREAM_DIR="${SAK_VULN_BANK_DIR:-$REPO_ROOT/vendor/external/vuln-bank}"
COMPOSE_FILE="$UPSTREAM_DIR/docker-compose.yml"
CHECKS_FILE="$SCRIPT_DIR/checks.json"
PLAYWRIGHT_SPEC="$SCRIPT_DIR/playwright/vuln-bank.spec.js"
DOC_PATH="docs/targets/vuln-bank.md"

MODE="dry-run"
TARGET=""
TUNNEL_URL=""
WEB_PORT="$DEFAULT_WEB_PORT"
HTTP_PORT="$DEFAULT_HTTP_PORT"
RUN_DIR=""
TIMEOUT="$DEFAULT_TIMEOUT"
DOWN=0
PURGE=0

usage() {
    cat <<EOF
Usage: sh targets/vuln-bank/run.sh [--dry-run|--execute] [options]

  --dry-run            print every step without Docker, network or browser (default)
  --execute            start the lab, wait for /healthz, then run the harness live
  --target URL         target origin (default: $DEFAULT_TARGET)
  --tunnel-url URL     owner-provided Legion/VPN or Mac tunnel origin; required for a
                       non-loopback target and must equal the target origin
  --port N             loopback host port for the web app (default: $DEFAULT_WEB_PORT)
  --http-port N        loopback host port for the upstream HTTP mapping (default: $DEFAULT_HTTP_PORT)
  --run-dir PATH       evidence directory (default: runs/vuln-bank-<UTC timestamp>)
  --timeout SECONDS    readiness timeout for /healthz (default: $DEFAULT_TIMEOUT)
  --down               stop the compose stack after the run (keeps the database volume)
  --purge              with --down, also remove the database volume (lab reset)
  -h, --help           this help

Live mode requires a checkout from clone.sh at $PINNED_COMMIT.
Loopback is the default; a tunnel URL is required for any non-loopback host.
See $DOC_PATH for accounts, scope, evidence and cleanup.
EOF
}

fail() {
    printf 'run: %s\n' "$*" >&2
    exit 1
}

info() {
    printf '%s\n' "$*"
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

numeric() {
    case "$1" in
        ''|*[!0-9]*) fail "$2 must be a positive integer, got: $1" ;;
    esac
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run) MODE="dry-run" ;;
        --execute) MODE="execute" ;;
        --target)
            shift
            [ "$#" -gt 0 ] || fail "--target needs a URL"
            TARGET=$1
            ;;
        --tunnel-url)
            shift
            [ "$#" -gt 0 ] || fail "--tunnel-url needs a URL"
            TUNNEL_URL=$1
            ;;
        --port)
            shift
            [ "$#" -gt 0 ] || fail "--port needs a number"
            WEB_PORT=$1
            ;;
        --http-port)
            shift
            [ "$#" -gt 0 ] || fail "--http-port needs a number"
            HTTP_PORT=$1
            ;;
        --run-dir)
            shift
            [ "$#" -gt 0 ] || fail "--run-dir needs a path"
            RUN_DIR=$1
            ;;
        --timeout)
            shift
            [ "$#" -gt 0 ] || fail "--timeout needs a number"
            TIMEOUT=$1
            ;;
        --down) DOWN=1 ;;
        --purge) PURGE=1 ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            fail "unknown argument: $1"
            ;;
    esac
    shift
done

numeric "$WEB_PORT" "--port"
numeric "$HTTP_PORT" "--http-port"
numeric "$TIMEOUT" "--timeout"
[ "$PURGE" = 0 ] || [ "$DOWN" = 1 ] || fail "--purge requires --down"

if [ -z "$TARGET" ]; then
    if [ -n "$TUNNEL_URL" ]; then
        TARGET=$TUNNEL_URL
    else
        TARGET=$DEFAULT_TARGET
    fi
fi
TARGET=${TARGET%/}
TUNNEL_URL=${TUNNEL_URL%/}

case "$TARGET" in
    http://*|https://*) ;;
    *) fail "target must be an http(s) URL: $TARGET" ;;
esac

TARGET_REST=${TARGET#*://}
TARGET_REST=${TARGET_REST%%/*}
TARGET_AUTHORITY=$TARGET_REST
TARGET_HOST=${TARGET_REST%:*}
TARGET_PORT=${TARGET_REST##*:}
case "$TARGET_REST" in
    *:*) ;;
    *) TARGET_PORT="80" ;;
esac
[ -n "$TARGET_HOST" ] || fail "cannot parse target host from: $TARGET"

case "$TARGET_HOST" in
    127.0.0.1|localhost|::1|\[::1\]) LOOPBACK=1 ;;
    *) LOOPBACK=0 ;;
esac

if [ "$LOOPBACK" = 0 ]; then
    [ -n "$TUNNEL_URL" ] || fail "non-loopback target $TARGET needs --tunnel-url naming the authorized tunnel origin"
    [ "$TUNNEL_URL" = "$TARGET" ] || fail "--tunnel-url ($TUNNEL_URL) must equal the target origin ($TARGET)"
fi

if [ -z "$RUN_DIR" ]; then
    RUN_DIR="$REPO_ROOT/runs/vuln-bank-$(date -u +%Y%m%dT%H%M%SZ)"
fi

print_plan() {
    info "vuln-bank harness (dry run)"
    info "target:      $TARGET"
    info "principal:   two lab users; see $DOC_PATH#test-accounts"
    info "upstream:    $UPSTREAM_URL"
    info "pinned:      $PINNED_COMMIT ($UPSTREAM_LICENSE license)"
    info "compose:     $COMPOSE_FILE"
    info "ports:       web $WEB_PORT (loopback), http $HTTP_PORT (loopback), postgres 5432 (upstream-pinned)"
    info "run dir:     $RUN_DIR"
    info "mode:        dry run (no Docker, no network, no browser)"
    info "would write: $RUN_DIR/scope.md"
    info "would write: $RUN_DIR/threat-model.md"
    info "would copy:  $CHECKS_FILE -> $RUN_DIR/checks.json"
    info "commands:"
    info "  1. (cd $UPSTREAM_DIR && VULNBANK_WEB_PORT=127.0.0.1:$WEB_PORT VULNBANK_HTTP_PORT=127.0.0.1:$HTTP_PORT docker compose up -d --build)"
    info "  2. wait for http://127.0.0.1:$WEB_PORT/healthz (up to ${TIMEOUT}s)"
    info "  3. uv run sak plan --suite web-blackbox --target $TARGET --run-dir $RUN_DIR"
    info "  4. uv run sak run --run $RUN_DIR --step nuclei --dry-run"
    info "  5. BASE_URL=$TARGET npx playwright test $PLAYWRIGHT_SPEC --reporter=json"
    info "  6. uv run sak findings import $RUN_DIR/findings/nuclei.json --run-dir $RUN_DIR"
    info "  7. uv run sak findings dedupe --write $RUN_DIR/findings.json"
    info "  8. uv run sak report $RUN_DIR"
    if [ "$DOWN" = 1 ]; then
        if [ "$PURGE" = 1 ]; then
            info "  9. (cd $UPSTREAM_DIR && docker compose down --volumes)"
        else
            info "  9. (cd $UPSTREAM_DIR && docker compose down)"
        fi
    fi
    info "notes:"
    info "  - clone the source first: sh targets/vuln-bank/clone.sh --dry-run"
    info "  - live mode: sh targets/vuln-bank/run.sh --execute"
    info "  - loopback by default; non-loopback targets need --tunnel-url"
    info "  - upstream pins postgres 5432:5432 on all interfaces; use an isolated host"
    exit 0
}

write_scope() {
    {
        printf '# Scope — vuln-bank (generated)\n\n'
        printf 'Generated by targets/vuln-bank/run.sh for %s.\n' "$TARGET"
        printf 'Pinned upstream revision: %s.\n\n' "$PINNED_COMMIT"
        printf '## Allowed hosts\n'
        printf -- '- %s\n' "$TARGET_AUTHORITY"
        if [ "$LOOPBACK" = 1 ] && [ "$TARGET_HOST" = "127.0.0.1" ]; then
            printf -- '- localhost:%s\n' "$TARGET_PORT"
        fi
        printf '\n## Out of scope\n'
        printf -- '- Any host not listed above\n'
        printf -- '- Internet-facing deployments and the upstream public demo\n'
        printf -- '- Direct Postgres access on 5432\n\n'
        printf '## Budget\n'
        printf -- '- max_requests: %s\n' "$REQUEST_BUDGET"
        printf -- '- max_seconds: %s\n\n' "$TIME_BUDGET"
        printf '## Rules of engagement\n'
        printf -- '- Authorized lab only; loopback or the owner-provided tunnel.\n'
        printf -- '- No brute force, denial of service or destructive writes.\n'
        printf -- '- Writes are serialized and need owner approval recorded in the run notes.\n'
        printf -- '- Stored payloads are benign and cleaned by the lab within 15 minutes.\n'
    } > "$RUN_DIR/scope.md"
}

write_threat_model() {
    {
        printf '# Threat model — vuln-bank\n\n'
        printf 'Target: %s\nPinned revision: %s\n\n' "$TARGET" "$PINNED_COMMIT"
        printf '## Assets\n'
        printf -- '- Session tokens and JWT claims issued by the login handler\n'
        printf -- '- Account balances, transaction history and loan records\n'
        printf -- '- Virtual card numbers, CVVs and card transaction history\n'
        printf -- '- Merchant API keys and merchant payment records\n'
        printf -- '- Uploaded profile files under static/uploads\n'
        printf -- '- Internal configuration exposed by /.env, /internal and the metadata routes\n'
        printf -- '- AI support context and its database access\n\n'
        printf '## Trust boundaries\n'
        printf -- '- Browser to Flask route: credentials, JWT bearer token and CSRF token\n'
        printf -- '- Flask route to Postgres: string-built SQL in login, billers and GraphQL resolvers\n'
        printf -- '- User object to admin object: account numbers, card ids and user ids\n'
        printf -- '- Flask to outbound URL fetch: /upload_profile_picture_url\n'
        printf -- '- Merchant client to /api/v1 payments: API key and raw card data\n'
        printf -- '- Anonymous chat client to the AI backend and its database tools\n\n'
        printf '## Invariants\n'
        printf -- '- A principal may read or mutate only objects it owns unless it is an admin.\n'
        printf -- '- Every balance change is authorised, positive where required and recorded once.\n'
        printf -- '- Tokens are signed, expire and cannot gain claims by client-side edits.\n'
        printf -- '- User-supplied paths and URLs never reach an internal file or network resource.\n'
        printf -- '- Stored markup is inert for every other user in the browser.\n'
        printf -- '- The assistant never discloses credentials, schema or other users data.\n'
    } > "$RUN_DIR/threat-model.md"
}

verify_upstream() {
    [ -e "$UPSTREAM_DIR/.git" ] || fail "no checkout at $UPSTREAM_DIR; run sh targets/vuln-bank/clone.sh"
    actual=$(git -C "$UPSTREAM_DIR" rev-parse HEAD 2>/dev/null) || fail "cannot read the checkout revision"
    [ "$actual" = "$PINNED_COMMIT" ] || fail "checkout is at $actual, expected $PINNED_COMMIT"
    [ -f "$COMPOSE_FILE" ] || fail "missing compose file: $COMPOSE_FILE"
    info "verified upstream checkout at $PINNED_COMMIT"
}

start_compose() {
    info "starting vuln-bank compose (web 127.0.0.1:$WEB_PORT, http 127.0.0.1:$HTTP_PORT)"
    ( cd "$UPSTREAM_DIR" && VULNBANK_WEB_PORT="127.0.0.1:$WEB_PORT" VULNBANK_HTTP_PORT="127.0.0.1:$HTTP_PORT" docker compose up -d --build )
}

wait_for_health() {
    info "waiting for $TARGET/healthz (up to ${TIMEOUT}s)"
    started=$(date +%s)
    while :; do
        if curl -fsS --max-time 5 "$TARGET/healthz" >/dev/null 2>&1; then
            info "healthz is ready"
            return 0
        fi
        now=$(date +%s)
        if [ $((now - started)) -ge "$TIMEOUT" ]; then
            ( cd "$UPSTREAM_DIR" && docker compose logs --tail 40 web db ) >&2 || true
            fail "healthz did not become ready within ${TIMEOUT}s"
        fi
        sleep 3
    done
}

stop_compose() {
    if [ "$PURGE" = 1 ]; then
        info "stopping compose and removing the lab volume"
        ( cd "$UPSTREAM_DIR" && docker compose down --volumes )
    else
        info "stopping compose (volume kept)"
        ( cd "$UPSTREAM_DIR" && docker compose down )
    fi
}

if [ "$MODE" = "dry-run" ]; then
    print_plan
fi

require_cmd git
require_cmd docker
require_cmd curl
require_cmd uv
docker compose version >/dev/null 2>&1 || fail "docker compose v2 is required"

verify_upstream

mkdir -p "$RUN_DIR"
info "run dir: $RUN_DIR"

start_compose
wait_for_health

write_scope
write_threat_model
cp "$CHECKS_FILE" "$RUN_DIR/checks.json"
info "wrote $RUN_DIR/scope.md, $RUN_DIR/threat-model.md and $RUN_DIR/checks.json"

(
    cd "$REPO_ROOT"
    uv run sak plan --suite web-blackbox --target "$TARGET" --run-dir "$RUN_DIR"
)

nuclei_planned=0
if [ -f "$RUN_DIR/plan.json" ] && (
    cd "$REPO_ROOT"
    uv run python - "$RUN_DIR/plan.json" <<'PY'
import json
import sys

plan = json.load(open(sys.argv[1], encoding="utf-8"))
candidates = plan.get("candidates") or []
raise SystemExit(0 if any(item.get("id") == "nuclei" for item in candidates) else 1)
PY
); then
    nuclei_planned=1
fi

if [ "$nuclei_planned" = 1 ]; then
    (
        cd "$REPO_ROOT"
        uv run sak run --run "$RUN_DIR" --step nuclei --execute
    )
else
    info "nuclei is not a plan candidate (missing binary or filtered); skipping the Nuclei step"
    info "install it with 'brew install nuclei' or run 'uv run sak doctor' for the exact command"
fi

if [ -f "$PLAYWRIGHT_SPEC" ] && command -v npx >/dev/null 2>&1; then
    info "running Playwright smoke checks against $TARGET"
    if BASE_URL="$TARGET" npx playwright test "$PLAYWRIGHT_SPEC" --reporter=json \
        > "$RUN_DIR/playwright-results.json" 2> "$RUN_DIR/playwright-stderr.log"; then
        info "playwright smoke checks passed"
    else
        info "playwright exited non-zero; see $RUN_DIR/playwright-results.json and playwright-stderr.log"
        info "a missing browser or test dependency is not a target finding"
    fi
else
    info "npx or the Playwright spec is missing; skipping Playwright (operator installs it)"
fi

if [ -f "$RUN_DIR/findings/nuclei.json" ]; then
    (
        cd "$REPO_ROOT"
        uv run sak findings import "$RUN_DIR/findings/nuclei.json" --run-dir "$RUN_DIR"
    )
else
    info "no Nuclei candidate findings to import"
fi

if [ -f "$RUN_DIR/findings.json" ]; then
    (
        cd "$REPO_ROOT"
        uv run sak findings dedupe --write "$RUN_DIR/findings.json"
    )
fi

(
    cd "$REPO_ROOT"
    uv run sak report "$RUN_DIR"
)

if [ "$DOWN" = 1 ]; then
    stop_compose
else
    info "lab left running; stop it with:"
    info "  (cd $UPSTREAM_DIR && docker compose down)"
    info "  add --volumes to reset the database"
fi

info "evidence: $RUN_DIR (scope.md, threat-model.md, plan.json, findings/, report)"
info "docs: $DOC_PATH"
