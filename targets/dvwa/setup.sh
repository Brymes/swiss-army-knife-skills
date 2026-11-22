#!/bin/sh
# Wait for DVWA, create/reset its database, log in, and set security to low.
#
# Loopback only. Credentials come from the environment or targets/dvwa/.env
# (ignored by git); they are never printed. The only output is non-secret status.
#
# Usage:
#   sh targets/dvwa/setup.sh [--dry-run] [--url http://127.0.0.1:8080]
#
# Environment:
#   DVWA_URL, DVWA_PORT, DVWA_USERNAME, DVWA_PASSWORD, DVWA_WAIT_SECONDS
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# Local operator values override the documented demo defaults.
if [ -f "$SCRIPT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$SCRIPT_DIR/.env"
  set +a
fi

PORT=${DVWA_PORT:-8080}
URL=${DVWA_URL:-http://127.0.0.1:$PORT}
USERNAME=${DVWA_USERNAME:-admin}
PASSWORD=${DVWA_PASSWORD:-password}
WAIT_SECONDS=${DVWA_WAIT_SECONDS:-120}
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: sh targets/dvwa/setup.sh [--dry-run] [--url URL]

Wait for DVWA, create/reset the database, log in as the configured admin and
set the security level to low. Credentials are read from DVWA_USERNAME and
DVWA_PASSWORD (or targets/dvwa/.env) and are never printed.

  --dry-run   print the plan without contacting the target
  --url URL   target base URL (default: DVWA_URL or http://127.0.0.1:8080)
  -h, --help  show this help
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

case "$URL" in
  http://*|https://*) ;;
  *)
    echo "error: --url must be an http(s) URL" >&2
    exit 2
    ;;
esac
URL=${URL%/}

case "$URL" in
  http://127.0.0.1|http://127.0.0.1:*|http://localhost|http://localhost:*|http://\[::1\]|http://\[::1\]:*) ;;
  *)
    echo "error: setup.sh is loopback-only in this harness ($URL); use http://127.0.0.1:8080 or an SSH tunnel" >&2
    exit 2
    ;;
esac

case "$WAIT_SECONDS" in
  ''|*[!0-9]*)
    echo "error: DVWA_WAIT_SECONDS must be a whole number of seconds" >&2
    exit 2
    ;;
esac

if [ "$DRY_RUN" -eq 1 ]; then
  cat <<EOF
dry run: DVWA setup
url: $URL
user: $USERNAME
plan:
  1. wait up to ${WAIT_SECONDS}s for /login.php
  2. create or reset the DVWA database through /setup.php
  3. log in as the configured account
  4. submit security=low through /security.php and verify it took effect
no request was sent; credentials, tokens and session ids are never printed
EOF
  exit 0
fi

command -v curl >/dev/null 2>&1 || {
  echo "error: curl is required for the live DVWA setup" >&2
  exit 1
}

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sak-dvwa-setup.XXXXXX")
COOKIES=$WORK_DIR/cookies.txt
HTML=$WORK_DIR/page.html
cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT HUP INT TERM

# Print the first DVWA user_token value from a saved page. Attribute order and
# single or double quotes are both accepted; the token is never logged.
token_from() {
  sed -n \
    -e "s/.*name=['\"]user_token['\"][^>]*value=['\"]\([^'\"]*\)['\"].*/\1/p" \
    -e "s/.*value=['\"]\([^'\"]*\)['\"][^>]*name=['\"]user_token['\"].*/\1/p" \
    "$1" | head -n 1
}

fetch() {
  curl -fsSL --max-time 20 --max-redirs 5 \
    -c "$COOKIES" -b "$COOKIES" "$1" -o "$HTML"
}

post() {
  # post <path> <referer path> <data...>
  target=$1
  referer=$2
  shift 2
  curl -fsSL --max-time 40 --max-redirs 5 \
    -c "$COOKIES" -b "$COOKIES" -e "$URL$referer" \
    "$@" "$URL$target" -o "$HTML"
}

echo "dvwa: waiting for $URL (up to ${WAIT_SECONDS}s)"
waited=0
while [ "$waited" -lt "$WAIT_SECONDS" ]; do
  if curl -fsS --max-time 5 -o /dev/null "$URL/login.php" 2>/dev/null; then
    break
  fi
  sleep 2
  waited=$((waited + 2))
done
if [ "$waited" -ge "$WAIT_SECONDS" ]; then
  echo "error: DVWA did not answer at $URL/login.php within ${WAIT_SECONDS}s" >&2
  echo "hint: docker compose -f targets/dvwa/compose.yaml up -d" >&2
  exit 1
fi

# 1. Create or reset the database. The setup page is reachable before login.
fetch "$URL/setup.php"
TOKEN=$(token_from "$HTML")
if [ -n "$TOKEN" ]; then
  post /setup.php /setup.php \
    --data-urlencode "create_db=Create / Reset Database" \
    --data-urlencode "user_token=$TOKEN"
else
  post /setup.php /setup.php \
    --data-urlencode "create_db=Create / Reset Database"
fi
echo "dvwa: database created or reset"

# 2. Log in with a fresh session after the reset.
fetch "$URL/login.php"
TOKEN=$(token_from "$HTML")
if [ -z "$TOKEN" ]; then
  echo "error: the DVWA login page did not provide a user_token" >&2
  exit 1
fi
post /login.php /login.php \
  --data-urlencode "username=$USERNAME" \
  --data-urlencode "password=$PASSWORD" \
  --data-urlencode "Login=Login" \
  --data-urlencode "user_token=$TOKEN"
if grep -qi "login failed" "$HTML"; then
  echo "error: DVWA rejected the configured login; check DVWA_USERNAME and DVWA_PASSWORD" >&2
  exit 1
fi
fetch "$URL/index.php"
if ! grep -qi "logout" "$HTML"; then
  echo "error: DVWA login did not establish an authenticated session" >&2
  exit 1
fi
echo "dvwa: login ok"

# 3. Set and verify the low security level.
fetch "$URL/security.php"
TOKEN=$(token_from "$HTML")
if [ -n "$TOKEN" ]; then
  post /security.php /security.php \
    --data-urlencode "security=low" \
    --data-urlencode "seclev_submit=Submit" \
    --data-urlencode "user_token=$TOKEN"
else
  post /security.php /security.php \
    --data-urlencode "security=low" \
    --data-urlencode "seclev_submit=Submit"
fi
fetch "$URL/security.php"
if ! grep -Eq "value=['\"]low['\"][^>]*selected|selected[^>]*value=['\"]low['\"]" "$HTML"; then
  echo "error: DVWA did not keep security=low" >&2
  exit 1
fi
echo "dvwa: security=low verified"

echo "dvwa: ready at $URL (user=$USERNAME, security=low)"
