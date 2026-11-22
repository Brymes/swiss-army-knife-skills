#!/bin/sh
# End-to-end DVWA low-security pilot harness.
#
# Live mode starts the loopback container (unless --no-compose), waits for and
# configures DVWA, writes scope and threat-model files, plans web-blackbox, runs
# the bounded Playwright browser step before Nuclei, imports candidate findings
# and renders the report. Dry-run mode only prints the command sequence.
#
# Usage:
#   sh targets/dvwa/run.sh --dry-run
#   sh targets/dvwa/run.sh
#   sh targets/dvwa/run.sh --no-compose --url http://127.0.0.1:8080
#   sh targets/dvwa/run.sh --run-dir runs/dvwa-pilot
#
# Live prerequisites are recorded in targets/dvwa/README.md. T1 (Playwright
# adapter) and T2 (findings import) must be present in the checkout.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../.." && pwd)
cd "$ROOT"

if [ -f "$HERE/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$HERE/.env"
  set +a
fi

PORT=${DVWA_PORT:-8080}
DEFAULT_URL=${DVWA_URL:-http://127.0.0.1:$PORT}
URL=$DEFAULT_URL
DRY_RUN=0
USE_COMPOSE=1
RUN_DIR=
WAIT_SECONDS=${DVWA_WAIT_SECONDS:-120}

usage() {
  cat <<'EOF'
Usage: sh targets/dvwa/run.sh [--dry-run] [--url URL] [--no-compose] [--run-dir DIR]

  --dry-run     print every planned command without starting Docker or touching
                the target (default is live)
  --url URL     target base URL; must be loopback (default: DVWA_URL or
                http://127.0.0.1:8080)
  --no-compose  skip the local Docker start, for the Mac SSH tunnel path
  --run-dir DIR run directory (default: runs/dvwa-<UTC timestamp>)
  -h, --help    show this help

Live mode needs uv, curl, Docker, Nuclei, Node/npx with Playwright, the T1
Playwright adapter and the T2 findings import command.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      ;;
    --url)
      [ $# -ge 2 ] || { echo "error: --url needs a value" >&2; exit 2; }
      URL=$2
      shift
      ;;
    --url=*)
      URL=${1#*=}
      ;;
    --no-compose)
      USE_COMPOSE=0
      ;;
    --run-dir)
      [ $# -ge 2 ] || { echo "error: --run-dir needs a value" >&2; exit 2; }
      RUN_DIR=$2
      shift
      ;;
    --run-dir=*)
      RUN_DIR=${1#*=}
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

URL=${URL%/}
case "$URL" in
  http://127.0.0.1|http://127.0.0.1:*|http://localhost|http://localhost:*|http://\[::1\]|http://\[::1\]:*) ;;
  *)
    echo "error: DVWA is loopback-only in this harness ($URL); use http://127.0.0.1:8080 or an SSH tunnel" >&2
    exit 2
    ;;
esac

# The scenario uses ${DVWA_USERNAME} and ${DVWA_PASSWORD}; export the resolved
# values for the Playwright runner. They are never printed.
USERNAME=${DVWA_USERNAME:-admin}
PASSWORD=${DVWA_PASSWORD:-password}
DVWA_URL=$URL
DVWA_USERNAME=$USERNAME
DVWA_PASSWORD=$PASSWORD
export DVWA_URL DVWA_USERNAME DVWA_PASSWORD

if [ -z "$RUN_DIR" ]; then
  RUN_DIR=$ROOT/runs/dvwa-$(date -u +%Y%m%dT%H%M%SZ)
else
  case "$RUN_DIR" in
    /*) ;;
    *) RUN_DIR=$ROOT/$RUN_DIR ;;
  esac
fi

if [ "$DRY_RUN" -eq 1 ]; then
  cat <<EOF
dry run: DVWA low-security harness
url: $URL
run dir: $RUN_DIR
plan:
EOF
  if [ "$USE_COMPOSE" -eq 1 ]; then
    echo "  1. docker compose -f targets/dvwa/compose.yaml up -d"
  else
    echo "  1. docker compose: skipped (--no-compose; use the Mac SSH tunnel)"
  fi
  cat <<EOF
  2. sh targets/dvwa/setup.sh --url $URL
     (wait for DVWA, reset the database, log in, set and verify security=low)
  3. write $RUN_DIR/scope.md and $RUN_DIR/threat-model.md
  4. uv run sak plan --suite web-blackbox --target $URL --run-dir $RUN_DIR --allow-missing-requires
  5. inject options.scenario=targets/dvwa/checks.json into the playwright plan step
  6. uv run sak run --run $RUN_DIR --step playwright --execute
  7. uv run sak run --run $RUN_DIR --step nuclei --execute
  8. uv run sak findings import $RUN_DIR/findings/nuclei.json --run-dir $RUN_DIR
  9. uv run sak findings import $RUN_DIR/findings/playwright.json --run-dir $RUN_DIR
 10. uv run sak report $RUN_DIR
no container was started and no request was sent; credentials are never printed
EOF
  exit 0
fi

command -v uv >/dev/null 2>&1 || {
  echo "error: uv is required; run: uv sync" >&2
  exit 1
}
command -v curl >/dev/null 2>&1 || {
  echo "error: curl is required for setup.sh" >&2
  exit 1
}
if [ "$USE_COMPOSE" -eq 1 ]; then
  command -v docker >/dev/null 2>&1 || {
    echo "error: docker is required unless --no-compose is used" >&2
    exit 1
  }
fi

# The test suite overrides SAK_CMD with a fake CLI; operators use the default.
sak() {
  if [ -n "${SAK_CMD:-}" ]; then
    "$SAK_CMD" "$@"
  else
    uv run sak "$@"
  fi
}

if [ "$USE_COMPOSE" -eq 1 ]; then
  echo "== start =="
  docker compose -f "$HERE/compose.yaml" up -d
else
  echo "== start =="
  echo "skipped local Docker; using the existing tunnel at $URL"
fi

echo
echo "== configure =="
if [ "${DVWA_SKIP_SETUP:-0}" = "1" ]; then
  echo "skipped setup (DVWA_SKIP_SETUP=1)"
else
  sh "$HERE/setup.sh" --url "$URL"
fi

echo
echo "== run directory =="
mkdir -p "$RUN_DIR/logs" "$RUN_DIR/steps" "$RUN_DIR/findings" "$RUN_DIR/evidence"
echo "$RUN_DIR"

cat > "$RUN_DIR/scope.md" <<SCOPE
# Scope — DVWA low-security harness

Authorization: a local Docker DVWA container owned by the operator; demo data only.
Accounts: the DVWA demo account configured in targets/dvwa/.env (ignored by git);
no real accounts or personal data.
Target level: DVWA security=low, used only to exercise the pilot pipeline.
Mode: blackbox, normal intensity.

## In scope

| Asset | Kind | Methods | Notes |
|---|---|---|---|
| $URL | web | GET, HEAD, POST | local DVWA |

## Out of scope

- Every other host and port.
- Cloud metadata, denial of service and brute force.
- Destructive actions beyond the DVWA database reset in setup.sh.

## Budget

- max_requests: 500
- max_seconds: 300
SCOPE

cat > "$RUN_DIR/threat-model.md" <<'THREAT'
# Threat model — DVWA low-security harness

## Assets

- DVWA administrator session and the demo user records
- SQL-backed user and guestbook data
- Reflected and stored page content rendered to the browser
- Files uploaded through the DVWA upload page
- The application's own database setup and reset actions

## Trust boundaries

- Anonymous request to the login and setup pages
- Authenticated user to administrator-only pages
- Client-supplied form input to SQL queries
- Client-supplied text to reflected and stored HTML
- Uploaded filename and content to the server filesystem
- Browser session cookie to server-side authorization

## Invariants

- Authentication is required before any vulnerability page is reachable
- The security level is enforced server-side and is not client-selectable alone
- User input is parameterized before it reaches SQL
- Untrusted text is encoded for its HTML output context
- Uploads are validated by type and never executed as code
- The session identifier is not exposed in logs, reports or evidence
THREAT

echo
echo "== plan =="
sak plan --suite web-blackbox --target "$URL" \
  --run-dir "$RUN_DIR" --allow-missing-requires

echo
echo "== playwright scenario =="
uv run python - "$RUN_DIR/plan.json" "$HERE/checks.json" <<'PY'
import json
import sys
from pathlib import Path

plan_path = Path(sys.argv[1])
scenario = Path(sys.argv[2]).resolve()
plan = json.loads(plan_path.read_text(encoding="utf-8"))
for candidate in plan.get("candidates") or []:
    if candidate.get("id") == "playwright":
        options = candidate.setdefault("options", {})
        options["scenario"] = str(scenario)
        options["timeout_seconds"] = 120
        break
else:
    raise SystemExit(
        "error: playwright is not a candidate in plan.json; "
        "merge the T1 Playwright adapter and rerun the plan"
    )
plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"playwright scenario: {scenario}")
PY

echo
echo "== playwright =="
sak run --run "$RUN_DIR" --step playwright --execute

echo
echo "== nuclei =="
NUCLEI_RC=0
sak run --run "$RUN_DIR" --step nuclei --execute || NUCLEI_RC=$?
if [ "$NUCLEI_RC" -ne 0 ]; then
  NUCLEI_WARNING="$RUN_DIR/logs/nuclei-warning.txt"
  {
    echo "warning: nuclei step exited $NUCLEI_RC (timed out, refused or failed)"
    echo "at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "action: continuing to candidate import and report; Nuclei artifacts are kept"
    echo "artifacts: $RUN_DIR/logs/nuclei.log, $RUN_DIR/findings/nuclei.json, $RUN_DIR/steps/nuclei.json"
  } > "$NUCLEI_WARNING"
  echo "warning: nuclei exited $NUCLEI_RC; recorded in $NUCLEI_WARNING" >&2
  echo "warning: continuing to import and report; Nuclei artifacts are kept" >&2
fi

echo
echo "== import candidates =="
if [ -f "$RUN_DIR/findings/nuclei.json" ]; then
  sak findings import "$RUN_DIR/findings/nuclei.json" --run-dir "$RUN_DIR"
else
  NUCLEI_WARNING="$RUN_DIR/logs/nuclei-warning.txt"
  {
    echo "warning: no nuclei candidate file at $RUN_DIR/findings/nuclei.json"
    echo "action: skipped the nuclei import and continued to the report"
  } >> "$NUCLEI_WARNING"
  echo "warning: no nuclei candidate file; skipped the nuclei import" >&2
fi
sak findings import "$RUN_DIR/findings/playwright.json" --run-dir "$RUN_DIR"

echo
echo "== report =="
sak report "$RUN_DIR"

echo
echo "dvwa pilot complete: $RUN_DIR/REPORT.md"
echo "reset with: docker compose -f targets/dvwa/compose.yaml down -v"
