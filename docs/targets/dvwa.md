# DVWA target guide

DVWA (Damn Vulnerable Web Application) is the pilot's authenticated web target.
The harness under [`targets/dvwa/`](../../targets/dvwa/) runs it on loopback,
sets the application to `security=low`, drives a real browser session and feeds
the resulting candidates into the normal `sak` findings and report pipeline.

The harness is for **authorized local testing only**. It binds `127.0.0.1`,
rejects non-loopback URLs and documents no external scanning. DVWA is
deliberately vulnerable demo software; use disposable data and remove the
container after the pilot.

## Overview

One command performs the full local flow:

```sh
sh targets/dvwa/run.sh --dry-run   # offline preview
sh targets/dvwa/run.sh            # live
```

Live mode:

1. starts `vulnerables/web-dvwa` with `docker compose`;
2. waits for the app, resets the DVWA database, logs in as the demo admin and
   sets/verifies `security=low`;
3. creates a run directory with `scope.md` and `threat-model.md`;
4. plans the `web-blackbox` suite and injects the Playwright scenario path;
5. runs the bounded Playwright step before Nuclei under the normal scope/budget
   gates, so a scan cannot exhaust the browser step's budget;
6. imports both candidate lists as `needs_validation` findings;
7. renders `REPORT.md`, `FINDINGS-DETAIL.md` and `NEEDS-VALIDATION.md`.

Dry-run mode starts nothing and sends no request. It is the offline check used
before any live action.

## Prerequisites

- `uv` and a synced checkout (`uv sync`)
- `curl`
- Docker with Compose v2 for the local path
- Nuclei with local templates (`brew install nuclei`, then a manual
  `nuclei -update-templates`)
- Node/npx with Playwright (`npm install --global playwright`,
  `npx playwright install chromium`)
- The T1 Playwright adapter and T2 `sak findings import` merged into the branch
- A route to Legion (Tailscale/SSH) for the Mac path

`sak doctor` reports each missing host tool with an install hint. The harness
does not install global tools.

**Live execution is a lead action after the dry-run and offline tests pass.**
It is not a worker test: the unit tests in `tests/test_target_dvwa.py` never
start Docker, open a browser or contact the target.

## Kali WSL — local Docker

Use a Kali WSL distribution with Docker available.

```sh
cd /path/to/swiss-army-knife-skills
cp targets/dvwa/.env.example targets/dvwa/.env
sh targets/dvwa/setup.sh --dry-run
sh targets/dvwa/run.sh
```

`targets/dvwa/.env` is ignored by git. `DVWA_PORT` changes the published
loopback port; the container port remains `80`. The default target is
`http://127.0.0.1:8080`.

If the app is not reachable from Windows while it works inside WSL, fix the WSL
networking or use the Mac tunnel path; do not bind the container to `0.0.0.0`.

## Mac tunnel — Legion

Run DVWA on Legion and forward its loopback port to the Mac:

```sh
ssh -L 8080:127.0.0.1:8080 legion-ts
```

Add `-N` if you do not need a shell on Legion
(`ssh -N -L 8080:127.0.0.1:8080 legion-ts`).

In a second terminal, run the harness without local Docker:

```sh
cd /path/to/swiss-army-knife-skills
sh targets/dvwa/run.sh --no-compose --url http://127.0.0.1:8080
```

The forwarded target is still `127.0.0.1` on the Mac, so the loopback guard and
the scope allowlist behave exactly as in the local path. `setup.sh` waits for
the tunnel, resets the remote DVWA database and sets the security level through
the tunnel. Close the tunnel with `Ctrl-C`.

## Start, stop and reset

```sh
# start
docker compose -f targets/dvwa/compose.yaml up -d

# status and health
docker compose -f targets/dvwa/compose.yaml ps

# stop, keep the container
docker compose -f targets/dvwa/compose.yaml stop

# remove the container
docker compose -f targets/dvwa/compose.yaml down

# full reset, including the writable layer
docker compose -f targets/dvwa/compose.yaml down -v
docker compose -f targets/dvwa/compose.yaml up -d
sh targets/dvwa/setup.sh
```

`setup.sh --dry-run` prints the wait/reset/login/security sequence without
contacting the target. Its live output is status only: database reset, login ok,
`security=low verified`. It never prints credentials, CSRF tokens or session ids.

## Test accounts

| Field | Value |
|---|---|
| Username | `admin` (or `DVWA_USERNAME`) |
| Password | `DVWA_PASSWORD` from `targets/dvwa/.env`; documented demo default `password` |
| Security | `low` |

`checks.json` uses `${DVWA_USERNAME}` and `${DVWA_PASSWORD}` substitution, so no
credential is stored in the scenario. The defaults are the public DVWA demo
values, not secrets and not production credentials.

## Security level

DVWA's `security=low` makes the bundled SQL injection and XSS pages reachable.
`setup.sh` submits `security=low` through `/security.php` and re-reads the page to
confirm the option is selected. A low setting is a test precondition, not a
finding.

## Scope

The generated `scope.md` authorizes only the configured loopback origin, for
example `http://127.0.0.1:8080`. It records:

- authorization: operator-owned local DVWA container, demo data only;
- accounts: the documented DVWA demo account, no real accounts;
- out of scope: every other host, cloud metadata, denial of service, brute force
  and destructive actions beyond the DVWA reset;
- mode: blackbox, normal intensity, bounded requests and time.

`run.sh` refuses a non-loopback URL before it starts anything. `sak run
--execute` independently checks `scope.md`, the plan and the request/time budget.

## Expected evidence

A healthy live run writes under `runs/dvwa-<timestamp>/`:

- `scope.md` and `threat-model.md` — the authorization boundary and DVWA assets,
  trust boundaries and invariants;
- `plan.json` — the `web-blackbox` portfolio with the Playwright scenario option;
- `logs/` and `steps/` — masked adapter logs and per-step records;
- `findings/nuclei.json` and `findings/playwright.json` — raw candidate lists;
- `findings.json` — schema-valid `needs_validation` records with hashed evidence;
- `evidence/` — sanitized evidence written by the importer;
- `REPORT.md` plus the detail and needs-validation reports.

Playwright evidence should show the login redirect, `/security.php` with `low`
selected, and HTTP 200 observations for `/vulnerabilities/sqli/`,
`/vulnerabilities/xss_r/` and `/vulnerabilities/xss_s/`. Cookies are recorded by
name only; session values and headers stay out of evidence.

Candidates remain `needs_validation`. A loaded page is not a confirmed finding;
promotion needs fresh replay and matching evidence, and `sak report` must show no
false `confirmed` count.

## Cleanup

```sh
docker compose -f targets/dvwa/compose.yaml down -v --remove-orphans
rm -rf runs/dvwa-<timestamp>
rm -f targets/dvwa/.env
```

Stop the Mac tunnel with `Ctrl-C`. Review any retained report or screenshot
before sharing; remove files that contain session material even if the tooling
masked the known secrets.

## Troubleshooting

- **Port already in use**: set `DVWA_PORT` in `targets/dvwa/.env`, keep
  `DVWA_URL` in sync, and rerun.
- **Setup times out**: the first start initializes MySQL; check
  `docker compose ... logs` and the healthcheck.
- **Login rejected after a reset**: rerun `setup.sh`; the reset invalidates prior
  sessions.
- **Playwright missing from the plan**: merge the T1 adapter and card, then
  rerun `run.sh` so the plan and injection see it.
- **`findings import` unknown**: merge the T2 change; the rest of the harness
  remains usable.
- **Tunnel drops mid-run**: restart the tunnel, rerun `setup.sh`, then rerun the
  step; do not widen the scope.
