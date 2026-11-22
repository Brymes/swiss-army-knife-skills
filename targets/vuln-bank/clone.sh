#!/bin/sh
# Clone the pinned vuln-bank upstream into vendor/external/vuln-bank.
#
# The checkout is external and gitignored: this repository never vendors upstream
# source. The script refuses to touch an existing checkout unless --reuse is given,
# and --reuse only verifies it; nothing is deleted or reset.
set -eu

UPSTREAM_URL="https://github.com/Commando-X/vuln-bank.git"
UPSTREAM_HTML="https://github.com/Commando-X/vuln-bank"
DEFAULT_BRANCH="main"
PINNED_COMMIT="41c5b056f9ae8a8b15c77ea79f1419356b321634"
EXPECTED_COMPOSE="docker-compose.yml"
EXPECTED_SERVICES="web db xss-cleaner autoheal"
EXPECTED_PORTS="5000 80 5432"
UPSTREAM_LICENSE="MIT"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
VENDOR_DIR="${SAK_VULN_BANK_DIR:-$REPO_ROOT/vendor/external/vuln-bank}"

DRY_RUN=0
REUSE=0

usage() {
    cat <<'EOF'
Usage: sh targets/vuln-bank/clone.sh [--dry-run] [--reuse] [--dir PATH]

  --dry-run   print the clone and verification commands without touching the network
  --reuse     verify an existing checkout instead of cloning; never resets or deletes it
  --dir PATH  checkout directory (default: vendor/external/vuln-bank, or $SAK_VULN_BANK_DIR)
  -h, --help  this help

The checkout is pinned to a commit and stays outside git. Existing checkouts are never
overwritten silently: remove one manually or pass --reuse to verify it.
EOF
}

fail() {
    printf 'clone: %s\n' "$*" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --reuse) REUSE=1 ;;
        --dir)
            shift
            [ "$#" -gt 0 ] || fail "--dir needs a path"
            VENDOR_DIR=$1
            ;;
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

verify_checkout() {
    actual=$(git -C "$VENDOR_DIR" rev-parse HEAD 2>/dev/null) || fail "not a git checkout: $VENDOR_DIR"
    [ "$actual" = "$PINNED_COMMIT" ] || fail "checkout is at $actual, expected $PINNED_COMMIT"
    [ -f "$VENDOR_DIR/$EXPECTED_COMPOSE" ] || fail "missing $EXPECTED_COMPOSE in $VENDOR_DIR"
    for service in $EXPECTED_SERVICES; do
        grep -q "^  $service:" "$VENDOR_DIR/$EXPECTED_COMPOSE" \
            || fail "compose file has no '$service' service"
    done
    grep -q 'VULNBANK_WEB_PORT' "$VENDOR_DIR/$EXPECTED_COMPOSE" \
        || fail "compose file does not expose VULNBANK_WEB_PORT"
    grep -q 'VULNBANK_HTTP_PORT' "$VENDOR_DIR/$EXPECTED_COMPOSE" \
        || fail "compose file does not expose VULNBANK_HTTP_PORT"
    grep -q '5432:5432' "$VENDOR_DIR/$EXPECTED_COMPOSE" \
        || fail "compose file does not publish postgres 5432"
    for port in $EXPECTED_PORTS; do
        grep -q "$port" "$VENDOR_DIR/$EXPECTED_COMPOSE" \
            || fail "compose file does not reference port $port"
    done
    [ -f "$VENDOR_DIR/LICENSE.md" ] || fail "missing LICENSE.md in $VENDOR_DIR"
    grep -qi "$UPSTREAM_LICENSE License" "$VENDOR_DIR/LICENSE.md" \
        || fail "LICENSE.md is not the expected $UPSTREAM_LICENSE license"
    printf 'verified %s at %s\n' "$VENDOR_DIR" "$PINNED_COMMIT"
}

if [ "$DRY_RUN" = 1 ]; then
    printf 'vuln-bank clone (dry run)\n'
    printf 'upstream:  %s\n' "$UPSTREAM_URL"
    printf 'branch:    %s\n' "$DEFAULT_BRANCH"
    printf 'commit:    %s\n' "$PINNED_COMMIT"
    printf 'license:   %s\n' "$UPSTREAM_LICENSE"
    printf 'checkout:  %s\n' "$VENDOR_DIR"
    printf 'compose:   %s/%s\n' "$VENDOR_DIR" "$EXPECTED_COMPOSE"
    printf 'ports:     web 5000, http 80, postgres 5432 (upstream defaults)\n'
    printf 'would run:\n'
    if [ -e "$VENDOR_DIR" ]; then
        printf '  # existing checkout detected; --reuse only verifies it, nothing is deleted\n'
        printf '  git -C %s rev-parse HEAD    # must equal %s\n' "$VENDOR_DIR" "$PINNED_COMMIT"
        printf '  test -f %s/%s\n' "$VENDOR_DIR" "$EXPECTED_COMPOSE"
    else
        printf '  mkdir -p %s\n' "$(dirname -- "$VENDOR_DIR")"
        printf '  git clone --branch %s %s %s\n' "$DEFAULT_BRANCH" "$UPSTREAM_URL" "$VENDOR_DIR"
        printf '  git -C %s checkout --detach %s\n' "$VENDOR_DIR" "$PINNED_COMMIT"
        printf '  git -C %s rev-parse HEAD    # must equal %s\n' "$VENDOR_DIR" "$PINNED_COMMIT"
        printf '  test -f %s/%s\n' "$VENDOR_DIR" "$EXPECTED_COMPOSE"
        printf '  grep -q VULNBANK_WEB_PORT %s/%s\n' "$VENDOR_DIR" "$EXPECTED_COMPOSE"
        printf '  grep -q 5432:5432 %s/%s\n' "$VENDOR_DIR" "$EXPECTED_COMPOSE"
    fi
    printf 'next: sh targets/vuln-bank/run.sh --dry-run\n'
    printf 'next (live, loopback): sh targets/vuln-bank/run.sh --execute\n'
    printf 'source stays external and gitignored under vendor/external/\n'
    exit 0
fi

command -v git >/dev/null 2>&1 || fail "git is not installed"

if [ -e "$VENDOR_DIR" ]; then
    if [ "$REUSE" = 1 ]; then
        printf 'reusing existing checkout: %s\n' "$VENDOR_DIR"
        verify_checkout
        printf 'next: sh targets/vuln-bank/run.sh --dry-run\n'
        exit 0
    fi
    fail "checkout already exists at $VENDOR_DIR; refusing to overwrite it. Use --reuse to verify it or remove it manually."
fi

mkdir -p "$(dirname -- "$VENDOR_DIR")"
printf 'cloning %s (branch %s) into %s\n' "$UPSTREAM_HTML" "$DEFAULT_BRANCH" "$VENDOR_DIR"
git clone --branch "$DEFAULT_BRANCH" "$UPSTREAM_URL" "$VENDOR_DIR"
git -C "$VENDOR_DIR" checkout --detach "$PINNED_COMMIT"
verify_checkout
printf 'next: sh targets/vuln-bank/run.sh --dry-run\n'
printf 'next (live, loopback): sh targets/vuln-bank/run.sh --execute\n'
