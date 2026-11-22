#!/bin/sh
# Dry-run wrapper around `sak engine <action> <id>`.
#
# Default: print the exact command and stop. Pass --execute to actually run it, which
# still goes through the engine card's requirement check and clean refusal.
#
#   ./engines/scripts/engine.sh list
#   ./engines/scripts/engine.sh doctor pentagi
#   ./engines/scripts/engine.sh install pentagi --execute
#   SAK_TARGET=legion SAK_LEGION_HOST=legion ./engines/scripts/engine.sh up pentagi
#
# Arguments are validated and passed as an argument vector. This script never builds a
# shell string from user input for local execution, and the remote path sends a quoted
# script over ssh stdin instead of interpolating values into an ssh command.
set -eu

usage() {
  cat <<'EOF'
usage: engine.sh <list|doctor|install|up|down|status> [engine-id] [--execute]

  --execute        run the command instead of printing it
  SAK_TARGET       local (default) or legion
  SAK_LEGION_HOST  ssh alias for SAK_TARGET=legion
  SAK_ROOT         absolute repository root on the target host (default: .)
                   quoted literally; ~ and $VARS are not expanded
EOF
}

execute=0
action=
engine_id=

for arg in "$@"; do
  case "$arg" in
    -h|--help)
      usage
      exit 0
      ;;
    --execute)
      execute=1
      ;;
    -*)
      printf 'error: unknown option: %s\n' "$arg" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [ -z "$action" ]; then
        action=$arg
      elif [ -z "$engine_id" ]; then
        engine_id=$arg
      else
        printf 'error: unexpected extra argument: %s\n' "$arg" >&2
        exit 2
      fi
      ;;
  esac
done

action=${action:-list}

case "$action" in
  list|doctor|install|up|down|status) ;;
  *)
    printf 'error: unknown action: %s\n' "$action" >&2
    usage >&2
    exit 2
    ;;
esac

case "$action" in
  list|doctor)
    if [ "$execute" -eq 1 ]; then
      printf 'error: --execute is only valid for install, up, down and status\n' >&2
      exit 2
    fi
    if [ "$action" = "list" ] && [ -n "$engine_id" ]; then
      printf 'error: list takes no engine id\n' >&2
      exit 2
    fi
    ;;
  *)
    if [ -z "$engine_id" ]; then
      printf 'error: %s needs an engine id\n' "$action" >&2
      exit 2
    fi
    ;;
esac

if [ -n "$engine_id" ]; then
  if ! printf '%s' "$engine_id" | LC_ALL=C grep -Eq '^[a-z0-9][a-z0-9._-]*$'; then
    printf 'error: invalid engine id: %s\n' "$engine_id" >&2
    exit 2
  fi
fi

# Print a value as one POSIX shell word. Used only to build the script that is piped to
# the remote shell, never for local execution.
quote() {
  printf "'"
  printf '%s' "$1" | awk 'BEGIN { ORS = "" } { gsub(/\047/, "\047\\\047\047"); print }'
  printf "'"
}

root=${SAK_ROOT:-.}

if [ "${SAK_TARGET:-local}" = "legion" ]; then
  if [ -z "${SAK_LEGION_HOST:-}" ]; then
    printf 'error: SAK_TARGET=legion needs SAK_LEGION_HOST=<ssh alias>\n' >&2
    exit 1
  fi

  # Fixed tokens only: action and engine id are validated above, and --execute is a
  # literal. Only SAK_ROOT needs quoting.
  script="cd $(quote "$root") && exec uv run sak engine $action"
  if [ -n "$engine_id" ]; then
    script="$script $engine_id"
  fi
  if [ "$execute" -eq 1 ]; then
    script="$script --execute"
  fi

  if [ "$execute" -eq 1 ]; then
    printf 'running on %s: %s\n' "$SAK_LEGION_HOST" "$script"
    printf '%s\n' "$script" | ssh "$SAK_LEGION_HOST" 'sh -s'
  else
    printf 'dry run (pass --execute to run): ssh %s sh -s < script\n' "$SAK_LEGION_HOST"
    printf '%s\n' "$script"
  fi
  exit 0
fi

if ! command -v uv >/dev/null 2>&1; then
  printf 'error: uv is not on PATH\n' >&2
  exit 1
fi

set -- run sak engine "$action"
if [ -n "$engine_id" ]; then
  set -- "$@" "$engine_id"
fi
if [ "$execute" -eq 1 ]; then
  set -- "$@" --execute
fi

render() {
  printf '%s' "$1"
  shift
  for word in "$@"; do
    printf ' %s' "$word"
  done
}

if [ "$execute" -eq 1 ]; then
  printf 'running: %s\n' "$(render "uv" "$@")"
  exec uv "$@"
fi

printf 'dry run (pass --execute to run): %s\n' "$(render "uv" "$@")"
printf 'requirements are checked by sak; nothing is installed globally.\n'
