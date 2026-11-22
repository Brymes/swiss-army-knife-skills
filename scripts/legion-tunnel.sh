#!/bin/sh
# SSH local-port forwards to the Legion host over Tailscale.
#
# Usage:
#   sh scripts/legion-tunnel.sh [--dry-run] [--host HOST] [PORT ...]
#   sh scripts/legion-tunnel.sh --check [--host HOST]
#   sh scripts/legion-tunnel.sh --execute [--host HOST] [PORT ...]
#
# Default host is legion-ts (a Tailscale MagicDNS/SSH alias). Default ports are
# 8080 3000 8000 (DVWA and two vuln-bank placeholders). Without --execute the
# script only prints the forwarding commands, so a dry run never opens a socket.
# --check is the one bounded remote probe: it runs
# `ssh -o BatchMode=yes <host> 'echo OK'` only when explicitly requested.
#
# The script takes no passwords, reads none from the environment, and passes
# every validated value as a distinct argv word. Ports are numeric and hosts are
# restricted to DNS/alias characters, so there is no extra shell interpolation.

set -u

HOST=legion-ts
MODE=print
PORTS=""
COUNT=0

usage() {
  cat <<'USAGE'
usage: sh scripts/legion-tunnel.sh [--dry-run] [--host HOST] [PORT ...]
       sh scripts/legion-tunnel.sh --check [--host HOST]
       sh scripts/legion-tunnel.sh --execute [--host HOST] [PORT ...]

  --dry-run    print the ssh -N -L commands; start nothing (the default)
  --execute    start the forwards in the foreground; Ctrl-C to stop
  --check      run one bounded `ssh -o BatchMode=yes HOST 'echo OK'` probe
  --host HOST  SSH/Tailscale host alias (default: legion-ts)
  --help       show this message

  PORT defaults to 8080 3000 8000. Each port is forwarded to 127.0.0.1 on
  the Legion host, for example:
    ssh -N -L 8080:127.0.0.1:8080 legion-ts
USAGE
}

say() {
  printf '%s\n' "$*"
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 2
}

validate_port() {
  case "$1" in
    ''|*[!0-9]*)
      fail "invalid port: $1"
      ;;
  esac
  if [ "$1" -lt 1 ] || [ "$1" -gt 65535 ]; then
    fail "invalid port: $1"
  fi
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run)
      MODE=print
      ;;
    --execute)
      MODE=execute
      ;;
    --check)
      MODE=check
      ;;
    --host)
      [ "$#" -ge 2 ] || fail "--host needs a value"
      HOST=$2
      shift
      ;;
    --host=*)
      HOST=${1#--host=}
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    -*)
      printf 'error: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
    *)
      # Validate before storing so a quoted argument such as "80 80" or
      # "80;id" is rejected instead of being word-split into valid ports.
      validate_port "$1"
      PORTS="$PORTS
$1"
      COUNT=$((COUNT + 1))
      ;;
  esac
  shift
done

# A host reaches ssh as one argv word. Reject empty values, leading dashes
# (which ssh would read as an option) and anything outside a conservative
# alias/DNS/address set.
case "$HOST" in
  ''|-*|*[!A-Za-z0-9._:-]*)
    fail "invalid host: $HOST"
    ;;
esac
[ -n "$HOST" ] || fail "invalid host: $HOST"

if [ "$COUNT" -eq 0 ]; then
  PORTS='8080
3000
8000'
fi

# Ports are newline-separated and were validated as they arrived, so a port
# argument can never inject a second word or option.
IFS='
'
for port in $PORTS; do
  validate_port "$port"
done

if [ "$MODE" = check ]; then
  say "check: ssh -o BatchMode=yes -o ConnectTimeout=5 $HOST 'echo OK'"
  ssh -o BatchMode=yes -o ConnectTimeout=5 "$HOST" 'echo OK'
  exit $?
fi

for port in $PORTS; do
  if [ "$MODE" = execute ]; then
    say "forwarding 127.0.0.1:$port to $HOST (Ctrl-C to stop)"
    ssh -N -L "$port:127.0.0.1:$port" "$HOST" || exit $?
  else
    printf 'ssh -N -L %s:127.0.0.1:%s %s\n' "$port" "$port" "$HOST"
  fi
done
