# DVWA low-security target harness

A loopback-only [Damn Vulnerable Web Application](https://github.com/digininja/DVWA)
target for the `sak` pilot. It exercises the authenticated browser path end to
end: DWVA database setup, admin login, `security=low`, the SQL injection and XSS
pages, Nuclei candidates, Playwright observations, findings import and report.

This harness is for authorized local testing only. It binds `127.0.0.1` and
refuses non-loopback URLs. The DVWA container is disposable demo software; never
point it at real data or expose the port beyond the host. The operator-facing
guide is [`docs/targets/dvwa.md`](../../docs/targets/dvwa.md).

## What is here

| Path | Purpose |
|---|---|
| `compose.yaml` | `vulnerables/web-dvwa` with a loopback port, named container and healthcheck |
| `.env.example` | documented DVWA demo defaults; copy to `.env` (ignored by git) |
| `setup.sh` | wait, reset the database, log in, set and verify `security=low` |
| `checks.json` | Playwright scenario: login, low security, SQLi/XSS page observations |
| `run.sh` | end-to-end live run or offline `--dry-run` |

All scripts are POSIX `sh` and support `--dry-run` where a live action would
otherwise happen. `setup.sh` and the Playwright scenario read
`DVWA_USERNAME`/`DVWA_PASSWORD` from the environment or `targets/dvwa/.env` and
never print them.

## Prerequisites

Live execution is a **lead action after the harness dry-run passes**, not a
worker test. The unit tests are offline and never start Docker.

- `uv` with the project synced (`uv sync`)
- `curl`
- Docker with Compose v2
- `nuclei` with local templates (`brew install nuclei`, then
  `nuclei -update-templates` as a manual operator step)
- Node/npx with Playwright (`npm install --global playwright`, then
  `npx playwright install chromium`)
- The T1 Playwright adapter (`adapters/playwright.py`) and the T2
  `sak findings import` command merged into the checkout
- `tar`/`sed`/`grep` from the host; no global install is performed by `sak`

## Configure

```sh
cd /path/to/swiss-army-knife-skills
cp targets/dvwa/.env.example targets/dvwa/.env
# edit targets/dvwa/.env if the port or demo account differs
```

`targets/dvwa/.env` is ignored by git. The documented defaults are the DVWA demo
account `admin` / `password` and port `8080`; do not reuse them anywhere real.
`compose.yaml` reads `DVWA_PORT` from that `.env` file, so changing the port does
not require editing the YAML.

## Kali WSL — local Docker path

Run everything inside the Kali WSL distribution where Docker is available.

```sh
cd /path/to/swiss-army-knife-skills

# start, configure, scan, import and report in one command
sh targets/dvwa/run.sh

# or step by step
docker compose -f targets/dvwa/compose.yaml up -d
sh targets/dvwa/setup.sh --url http://127.0.0.1:8080
uv run sak plan --suite web-blackbox --target http://127.0.0.1:8080 \
  --run-dir runs/dvwa-pilot --allow-missing-requires
```

From WSL, `127.0.0.1:8080` is reachable in both Windows and WSL when Docker
publishes to loopback inside the same WSL network. Do not change the bind to
`0.0.0.0` to "make it work"; fix the WSL/port-forwarding path instead.

## Mac — SSH tunnel to Legion

Run the container on Legion, then forward its loopback port to the Mac. The
target stays loopback from the Mac's point of view, so the harness safety checks
and scope allowlist still apply.

On the Mac:

```sh
ssh -L 8080:127.0.0.1:8080 legion-ts
```

Add `-N` if you do not need a shell on Legion (`ssh -N -L 8080:127.0.0.1:8080 legion-ts`).
Leave that terminal open. In a second terminal:

```sh
cd /path/to/swiss-army-knife-skills
sh targets/dvwa/run.sh --no-compose --url http://127.0.0.1:8080
```

`--no-compose` skips the local Docker start; `setup.sh` still waits for the
tunnel, resets the DVWA database and sets `security=low` through the forwarded
port. Stop the tunnel with `Ctrl-C` in the first terminal.

Alternative: run the whole harness on Legion and only open the tunnel to inspect
the app in a Mac browser.

## Start, stop and reset

```sh
# start
docker compose -f targets/dvwa/compose.yaml up -d

# health and logs
docker compose -f targets/dvwa/compose.yaml ps
docker compose -f targets/dvwa/compose.yaml logs --tail=50 dvwa

# stop, keep the container filesystem
docker compose -f targets/dvwa/compose.yaml stop

# stop and remove the container (the next start is a clean DVWA image)
docker compose -f targets/dvwa/compose.yaml down

# full reset: remove the container and its writable layer, then set up again
docker compose -f targets/dvwa/compose.yaml down -v
docker compose -f targets/dvwa/compose.yaml up -d
sh targets/dvwa/setup.sh
```

`setup.sh` also resets the DVWA database through `/setup.php`, which restores
the demo `admin` account and clears prior application state without removing the
container.

## Test accounts and security level

- Username: `admin`
- Password: the value of `DVWA_PASSWORD` in `targets/dvwa/.env` (documented demo
  default `password`)
- Security level: `low`, set by `setup.sh` and re-checked through `/security.php`
- The Playwright scenario logs in with `${DVWA_USERNAME}` /
  `${DVWA_PASSWORD}` substitution; no credential is stored in `checks.json`

The low level exists to make the known DVWA issues reachable. It is not a
finding by itself, and the harness does not attempt brute force or destructive
payloads.

## Run the harness

```sh
# offline preview; starts nothing and sends no request
sh targets/dvwa/run.sh --dry-run

# live: start/wait/setup, scope/threat model, plan, Playwright, Nuclei,
# candidate import and report
sh targets/dvwa/run.sh

# named run directory for evidence retention
sh targets/dvwa/run.sh --run-dir runs/dvwa-2026-11-15
```

Live output is written under the run directory:

```text
runs/dvwa-<timestamp>/
  scope.md               loopback target only
  threat-model.md        DVWA assets, boundaries and invariants
  plan.json              web-blackbox plan with the Playwright scenario option
  logs/                  masked adapter logs and run JSON
  steps/                 per-step records
  findings/              raw adapter candidate lists
  findings.json          schema-valid imported candidates (needs_validation)
  evidence/              hashed evidence written by findings import
  REPORT.md              rendered report
```

## Scope and expected evidence

Scope is the single loopback origin in `scope.md`; every `sak run --execute`
step must match that host and port. Expected evidence from a healthy live run:

- `setup.sh` reports `database created or reset`, `login ok` and
  `security=low verified`, with no token or session id in the output
- Nuclei writes candidate JSONL/JSON under `runs/<run>/findings/nuclei.json`
- Playwright writes per-step status, URL, title, status code and selected text;
  the scenario confirms the login page, `/security.php` with `low` selected, and
  the SQLi, reflected XSS and stored XSS pages
- `findings.json` contains schema-valid `needs_validation` candidates, not
  `confirmed` findings; a browser observation is evidence to verify, not a
  verdict
- `REPORT.md`, `FINDINGS-DETAIL.md` and `NEEDS-VALIDATION.md` render the run

A DVWA page loading is not a vulnerability finding. Promotion to `confirmed`
requires fresh replay and evidence that matches the finding schema.

## Cleanup

```sh
docker compose -f targets/dvwa/compose.yaml down -v --remove-orphans
rm -rf runs/dvwa-<timestamp>
```

Remove `targets/dvwa/.env` if it holds anything beyond the disposable demo
defaults. Keep the rendered report only if it contains no session tokens or raw
credentials; `sak` masks known secrets, but review evidence before sharing.

## Troubleshooting

- `DVWA did not answer`: check `docker compose ... ps`, the healthcheck and the
  host port in `targets/dvwa/.env`.
- `DVWA rejected the configured login`: reset the database with
  `down -v`/`up -d`, then rerun `setup.sh`.
- `playwright is not a candidate in plan.json`: merge the T1 adapter and card,
  then rerun the plan.
- `missing tool for playwright`: run `npx playwright install chromium`; `sak`
  never installs it for you.
- `findings import` is unknown: the T2 change is not in this checkout yet.
