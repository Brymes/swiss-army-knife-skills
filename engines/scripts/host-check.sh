#!/bin/sh
# Report the host prerequisites for the optional engines.
#
# Read-only: this script never installs, starts or pulls anything. It prints what is
# present and the exact install hint for what is missing, so the operator decides.
set -u

have() { command -v "$1" >/dev/null 2>&1; }
say() { printf '%s\n' "$1"; }
row() { printf '  %-18s %s\n' "$1" "$2"; }

say "sak engine host check ($(uname -s) $(uname -m))"

say ""
say "Container runtimes"
if have docker; then
  row docker "$(command -v docker)"
  if docker compose version >/dev/null 2>&1; then
    row "docker compose" "available"
  else
    row "docker compose" "missing (install Docker Desktop or OrbStack)"
  fi
  if docker info >/dev/null 2>&1; then
    row "daemon" "running"
  else
    row "daemon" "not running (start Docker Desktop or OrbStack)"
  fi
  if have docker && docker context show >/dev/null 2>&1; then
    row "context" "$(docker context show 2>/dev/null || echo default)"
  fi
else
  row docker "missing"
fi
if have container; then
  row "apple container" "available (single containers only; no Compose support)"
else
  row "apple container" "missing (optional, macOS 26+ on Apple silicon)"
fi
if have orb; then
  row orbstack "available"
elif [ -d /Applications/OrbStack.app ]; then
  row orbstack "installed (app present; CLI not on PATH)"
else
  row orbstack "not detected"
fi
if [ -d /Applications/Docker.app ]; then
  row "docker desktop" "installed (app present)"
else
  row "docker desktop" "not detected"
fi

say ""
say "Engine runtimes"
if have node; then
  row node "$(node --version 2>/dev/null)"
  row npm "$(npm --version 2>/dev/null || echo missing)"
else
  row node "missing (needed for the T3MP3ST npm path)"
fi
if have psql; then
  row postgres "psql $(psql --version 2>/dev/null | awk '{print $3}')"
else
  row postgres "missing (only the ARTEX local-build path needs a host Postgres)"
fi

say ""
say "Install hints (run them yourself; sak never installs)"
say "  Docker Desktop   brew install --cask docker"
say "  OrbStack         brew install --cask orbstack"
say "  Apple container  https://developer.apple.com/container/ (no Compose support)"
say "  Node             brew install node   # or nvm"
say "  Postgres         brew install postgresql@17"

say ""
say "Remote host (the Legion or any Linux Docker host)"
say "  export SAK_LEGION_HOST=legion            # ssh alias"
say "  ssh \"\$SAK_LEGION_HOST\" 'cd ~/swiss-army-knife-skills && uv run sak engine doctor'"
say "  ssh -L 8443:127.0.0.1:8443 \"\$SAK_LEGION_HOST\"   # tunnel a UI back to your laptop"
exit 0
