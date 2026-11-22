#!/bin/sh
# Install the sak CLI and its MIT agent skills.
#
# Usage:
#   sh install.sh --dry-run          # plan only; no writes, no uv sync
#   sh install.sh --local            # project install into .opencode/skills
#   sh install.sh --global           # user install into ~/.agents/skills
#   sh install.sh                    # same as --local
#
# Modes may be combined with --dry-run. The installer syncs the Python
# environment with uv, links the swiss-army-knife meta-skill and links only
# vendored skills whose LICENSE is MIT. GPL, AGPL and unlicensed directories are
# refused, never copied. The script never prints environment values or secrets.

set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODE=local
DRY_RUN=0
TARGET=""
PLANNED=0
LINKED=0
REFUSED=0
CONFLICT=0

usage() {
  cat <<'USAGE'
usage: sh install.sh [--local | --global] [--dry-run]

  --local      link skills into ./.opencode/skills (default)
  --global     link skills into ~/.agents/skills
  --dry-run    print the uv sync and link plan; change nothing
  --help       show this message
USAGE
}

say() {
  printf '%s\n' "$*"
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --local)
      MODE=local
      ;;
    --global)
      MODE=global
      ;;
    --dry-run)
      DRY_RUN=1
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'error: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [ "$MODE" = "global" ]; then
  [ -n "${HOME:-}" ] || fail "--global needs HOME to be set"
  TARGET="$HOME/.agents/skills"
else
  TARGET="$ROOT/.opencode/skills"
fi

command -v uv >/dev/null 2>&1 || fail "uv is not installed; see https://docs.astral.sh/uv/"

# Classify a license file without copying or modifying it.
license_kind() {
  _file=$1
  [ -f "$_file" ] || { printf 'none'; return; }
  if head -n 5 "$_file" 2>/dev/null | grep -qi 'GNU AFFERO GENERAL PUBLIC LICENSE'; then
    printf 'AGPL'
  elif head -n 5 "$_file" 2>/dev/null | grep -qi 'GNU GENERAL PUBLIC LICENSE'; then
    printf 'GPL'
  elif head -n 5 "$_file" 2>/dev/null | grep -qi 'MIT License'; then
    printf 'MIT'
  else
    printf 'other'
  fi
}

plan_line() {
  printf '[dry-run] %s\n' "$*"
}

link_skill() {
  _name=$1
  _source=$2
  _license_file=$3
  _destination=$TARGET/$_name

  if [ ! -d "$_source" ]; then
    say "skipped: $_name ($_source is missing)"
    return
  fi
  if [ ! -f "$_source/SKILL.md" ]; then
    say "refused: $_name (no SKILL.md entry point)"
    REFUSED=$((REFUSED + 1))
    return
  fi

  _kind=$(license_kind "$_license_file")
  case "$_kind" in
    MIT)
      ;;
    AGPL|GPL)
      say "refused: $_name ($_kind license; not MIT, not linked)"
      REFUSED=$((REFUSED + 1))
      return
      ;;
    none)
      say "refused: $_name (no license file; not linked)"
      REFUSED=$((REFUSED + 1))
      return
      ;;
    *)
      say "refused: $_name (license is not MIT; not linked)"
      REFUSED=$((REFUSED + 1))
      return
      ;;
  esac

  PLANNED=$((PLANNED + 1))
  if [ "$DRY_RUN" -eq 1 ]; then
    plan_line "would link: $_name (MIT) $_source -> $_destination"
    return
  fi

  if [ ! -d "$TARGET" ]; then
    mkdir -p "$TARGET" || fail "cannot create $TARGET"
  fi

  # Never replace a real directory or file the user owns.
  if [ -e "$_destination" ] && [ ! -L "$_destination" ]; then
    say "refused: $_name ($_destination exists and is not a symlink; move it first)"
    CONFLICT=$((CONFLICT + 1))
    return
  fi

  if ! ln -sfn "$_source" "$_destination"; then
    say "failed: $_name (cannot link $_destination)"
    CONFLICT=$((CONFLICT + 1))
    return
  fi
  LINKED=$((LINKED + 1))
  say "linked: $_name (MIT) -> $_destination"
}

say "sak installer"
say "mode: $MODE"
say "checkout: $ROOT"
say "skills target: $TARGET"
say "sync: uv sync"
if [ "$DRY_RUN" -eq 1 ]; then
  say "dry-run: no filesystem changes and no uv sync"
  plan_line "would sync: uv sync"
else
  say "running: uv sync"
  ( cd "$ROOT" && uv sync ) || fail "uv sync failed"
fi

# The meta-skill is our own MIT code; its license is the repository LICENSE.
link_skill "swiss-army-knife" "$ROOT/skills/swiss-army-knife" "$ROOT/LICENSE"

# Vendored skills: MIT only. vendor/external is gitignored and never scanned.
for _dir in "$ROOT"/vendor/skills/*; do
  [ -d "$_dir" ] || continue
  link_skill "$(basename "$_dir")" "$_dir" "$_dir/LICENSE"
done

if [ "$DRY_RUN" -eq 1 ]; then
  say "planned: $PLANNED MIT skill(s); refused: $REFUSED; conflicts: 0"
else
  say "installed: $LINKED skill(s); refused: $REFUSED; conflicts: $CONFLICT"
fi

if [ "$CONFLICT" -gt 0 ]; then
  printf 'error: %s destination conflict(s); nothing was overwritten\n' "$CONFLICT" >&2
  exit 2
fi
if [ "$REFUSED" -gt 0 ]; then
  printf 'error: %s skill(s) refused for license or layout; only MIT skills are linked\n' "$REFUSED" >&2
  exit 3
fi

say "next: uv run sak doctor"
say "next: uv run sak catalog validate"
exit 0
