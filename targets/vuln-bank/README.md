# vuln-bank target harness

Deliberately vulnerable banking lab (web, API, GraphQL and LLM surfaces) for authorized
local assessment. Upstream source stays **external and gitignored** under
`vendor/external/vuln-bank`; this directory holds only the harness.

> The lab is intentionally vulnerable. Run it on loopback or an owner-approved
> Legion/VPN tunnel only. Never expose it to the internet or load real data.

## Pin

| Field | Value |
|---|---|
| Upstream | <https://github.com/Commando-X/vuln-bank> |
| Clone URL | `https://github.com/Commando-X/vuln-bank.git` |
| Default branch | `main` |
| Pinned commit | `41c5b056f9ae8a8b15c77ea79f1419356b321634` |
| License | MIT (`LICENSE.md` upstream) |
| Checkout | `vendor/external/vuln-bank` (gitignored) |

The pin is recorded in `clone.sh`, `checks.json` and
[`docs/targets/vuln-bank.md`](../../docs/targets/vuln-bank.md). Do not move it without
re-validating the compose contract and the README.

## Files

| File | Purpose |
|---|---|
| `clone.sh` | Clone the upstream at the pinned commit, verify compose/services/ports and print the next command. `--dry-run` is offline; `--reuse` verifies an existing checkout and never resets it. |
| `run.sh` | Start compose on loopback, wait for `/healthz`, write `scope.md` and `threat-model.md`, plan `web-blackbox`, run Nuclei and Playwright, import candidates, dedupe and render a report. Dry run is the default. |
| `checks.json` | Machine-readable target contract: pin, services, ports, health route and the scenario list with actions, expected signal, severity and approval flags. |
| `scope.example.md` | Example authorization envelope and budget for the loopback lab. |
| `playwright/vuln-bank.spec.js` | Two readiness/evidence checks: `/healthz` and the login page. No credentials, writes or destructive actions. |
| `docs/targets/vuln-bank.md` | Operator guide: Kali-local and Mac-tunnel paths, accounts, scope, evidence, cleanup. |

## Quick start

```sh
# 1. Offline checks: no network, no Docker
sh targets/vuln-bank/clone.sh --dry-run
sh targets/vuln-bank/run.sh --dry-run

# 2. Fetch the pinned upstream into vendor/external/vuln-bank
sh targets/vuln-bank/clone.sh

# 3. Live loopback run (Docker, scope and budgets apply)
sh targets/vuln-bank/run.sh --execute

# 4. Stop the lab (keeps the database volume)
(cd vendor/external/vuln-bank && docker compose down)

# 5. Reset the lab database
(cd vendor/external/vuln-bank && docker compose down --volumes)
```

`run.sh --execute` binds the web app to `127.0.0.1:5000` and the upstream HTTP mapping to
`127.0.0.1:8080` by overriding `VULNBANK_WEB_PORT`/`VULNBANK_HTTP_PORT` at compose time.
Override with `--port` and `--http-port`, for example when 5000 is busy.

## Services and ports

| Service | Image | Upstream host port | Notes |
|---|---|---|---|
| `web` | built from `Dockerfile` | `${VULNBANK_WEB_PORT:-5000}:5000` | Flask dev server with `debug=True`; health at `/healthz` |
| `web` (second mapping) | same | `${VULNBANK_HTTP_PORT:-80}:5000` | Harness moves it to `127.0.0.1:8080` |
| `db` | `postgres:13` | `5432:5432` | Hardcoded on all interfaces upstream; the harness never queries it |
| `xss-cleaner` | built from `Dockerfile` | none | Cleans stored XSS payloads after 15 minutes |
| `autoheal` | `willfarrell/autoheal:latest` | none | Mounts `docker.sock`; restarts unhealthy containers |

Startup command (upstream README): `docker-compose up -d --build`; the harness uses
`docker compose up -d --build` with loopback port overrides.

> **Known limitation:** the upstream compose pins Postgres `5432:5432` on every interface
> and the harness must not edit the external checkout. Run the lab on an isolated host, or
> block 5432 at the host firewall. If 5432 is already taken, stop the local Postgres first.

## Flows

### Kali-local

Run everything on the Kali host: clone, `run.sh --execute`, then evidence lands under
`runs/vuln-bank-<UTC>/`. No tunnel is involved.

### Mac + tunnel

Two supported shapes:

```sh
# A. Harness on the Mac, lab on Kali reached through an SSH local forward
ssh -N -L 5000:127.0.0.1:5000 <owner-approved-legion-host>
sh targets/vuln-bank/run.sh --execute            # target stays http://127.0.0.1:5000

# B. Harness on the Mac (or Kali), lab reached through an owner-provided tunnel origin
sh targets/vuln-bank/run.sh --execute --tunnel-url http://<legion-host>:5000
```

A non-loopback target is refused unless `--tunnel-url` equals the target origin. The
tunnel origin is written into the generated `scope.md`; only that host is allowed.

## Evidence

`run.sh` writes into the run directory:

```
runs/vuln-bank-<UTC>/
  scope.md               # generated allowlist and budget
  threat-model.md        # assets, trust boundaries, invariants
  checks.json            # copy of the scenario contract
  plan.json              # sak web-blackbox plan
  findings/nuclei.json   # sanitized candidate findings
  steps/, logs/          # sanitized adapter command and output
  findings.json           # deduped candidates
  REPORT.md              # rendered report
  FINDINGS-DETAIL.md     # per-finding evidence view
  NEEDS-VALIDATION.md    # verifier queue
  playwright-results.json # browser smoke results when Playwright is installed
```

Candidate findings stay `needs_validation` until a fresh verifier reproduces each claim.
Expected evidence per scenario is listed in `checks.json`; the PIN brute-force scenario is
disabled by default and needs explicit owner approval.

## Accounts

See [`docs/targets/vuln-bank.md#test-accounts`](../../docs/targets/vuln-bank.md#test-accounts).
Default lab credentials are documented, never used outside the lab and never committed as
`.env` secrets.

## Safety

- Authorized lab only; loopback or an owner-approved tunnel.
- No brute force, denial of service or destructive writes. Writes need approval and are
  serialized.
- `nuclei` runs through `sak run --execute`, which enforces `scope.md` and the budget.
- Playwright browsers, Node packages and upstream source are installed by the operator and
  never committed.
- Stop on scope or account mismatch, or an unapproved write.
