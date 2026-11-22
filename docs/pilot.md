# Pilot runbook — DVWA and vuln-bank

Consolidated operator runbook for the `sak` pilot. It joins the accepted harnesses
from T1 (Playwright adapter), T2 (`sak findings import`), T3 (DVWA), T4
(vuln-bank) and T5 (Legion tunnel) into one tested command sequence.

Read this with:

- [`targets/pilot/README.md`](../targets/pilot/README.md) — target index: pins,
  ports, credential locations, scope, run and cleanup commands.
- [`targets/pilot/acceptance.md`](../targets/pilot/acceptance.md) — the four-cell
  acceptance matrix with exact evidence paths.
- [`docs/targets/dvwa.md`](targets/dvwa.md),
  [`docs/targets/vuln-bank.md`](targets/vuln-bank.md) and
  [`docs/targets/legion-tailscale.md`](targets/legion-tailscale.md) — per-target
  detail.

All commands run from the repository root. No command installs a global tool,
prints a credential or contacts a host other than loopback or the authorized
Legion path.

## 1. Status and honesty statement

The pilot has two kinds of results:

| Kind | Who runs it | Meaning |
|---|---|---|
| Offline baseline | worker, in this branch | dry-runs, static checks and unit tests pass |
| Live cell | **lead**, after merge | real Docker target, real browser and a rendered report |

The live cells in the acceptance matrix are marked `lead-run`. They are **not**
worker test results. A worker never starts Docker, opens a browser or an SSH
tunnel to claim a cell passed.

Current tested baseline (2026-11-15, branch `sp/T6-pilot-docs`):

- `sh targets/dvwa/run.sh --dry-run` exits `0` and prints the ten-step DVWA plan.
- `sh targets/vuln-bank/run.sh --dry-run` exits `0` and prints the eight-step
  vuln-bank plan.
- `sh scripts/legion-tunnel.sh --dry-run` exits `0` and prints the three default
  forwards; `--dry-run 5000` prints the vuln-bank forward.
- `uv run pytest -q` passes for the merged T1–T5 suites and this task's docs
  checks.

Not proven by the worker, and the reason the matrix exists:

- a live DVWA or vuln-bank container start, healthcheck and database reset;
- a real Chromium run through the Playwright adapter and the vuln-bank spec;
- a live `ssh -N -L` tunnel from the Mac to `legion-ts`;
- imported live candidates, dedupe and a rendered `REPORT.md` from a live run.

## 2. Prerequisites

| Tool | Needed for | Check |
|---|---|---|
| `uv` with a synced checkout | every `sak` command | `uv sync` |
| `curl` | readiness and DVWA setup | `curl --version` |
| Docker with Compose v2 | Kali-local and Legion-local targets | `docker compose version` |
| `nuclei` with local templates | Nuclei candidates | `uv run sak doctor` |
| Node and `npx` | Playwright | `npx --version` |
| Playwright and Chromium | browser evidence | `npm install --global playwright` then `npx playwright install chromium` |
| SSH key access to `legion-ts` | Mac tunnel cells | `ssh legion-ts 'echo OK'` |

`sak doctor` prints the exact install hint for every missing host tool. Neither
`sak` nor the harnesses install anything globally.

The DVWA demo account is read from `targets/dvwa/.env` (copied from
`targets/dvwa/.env.example` and ignored by git). The vuln-bank lab accounts are
listed in `docs/targets/vuln-bank.md#test-accounts`. Neither file contains a real
credential, and no credential belongs in a command, scope file, log or report.

## 3. Path A — Kali WSL with local Docker

Use this path when the suite, Docker and the targets all live in the same Kali
WSL distribution. It needs no tunnel.

```sh
docker info
uv run sak doctor
[ -f targets/dvwa/.env ] || cp targets/dvwa/.env.example targets/dvwa/.env
```

The `cp` runs only when `.env` is absent; keep an existing file and edit the port
there instead.

### 3.1 DVWA on Kali

```sh
sh targets/dvwa/run.sh --dry-run
sh targets/dvwa/run.sh --run-dir runs/pilot-dvwa-kali
```

The second command starts `vulnerables/web-dvwa` on `127.0.0.1:8080`, resets the
database, logs in, sets and verifies `security=low`, plans `web-blackbox`, runs
Nuclei and the Playwright scenario, imports both candidate lists and renders the
report. Expected evidence is under `runs/pilot-dvwa-kali/`:

```text
runs/pilot-dvwa-kali/scope.md
runs/pilot-dvwa-kali/threat-model.md
runs/pilot-dvwa-kali/plan.json
runs/pilot-dvwa-kali/logs/nuclei.log
runs/pilot-dvwa-kali/logs/playwright.log
runs/pilot-dvwa-kali/steps/nuclei.json
runs/pilot-dvwa-kali/steps/playwright.json
runs/pilot-dvwa-kali/findings/nuclei.json
runs/pilot-dvwa-kali/findings/playwright.json
runs/pilot-dvwa-kali/findings.json
runs/pilot-dvwa-kali/evidence/                 # one F-...-candidate.json per imported record
runs/pilot-dvwa-kali/REPORT.md
runs/pilot-dvwa-kali/FINDINGS-DETAIL.md
runs/pilot-dvwa-kali/NEEDS-VALIDATION.md
```

The evidence file names are derived from the imported finding ids, so they are
read from the run rather than predicted. Any file under `runs/` stays out of
git.

### 3.2 vuln-bank on Kali

```sh
sh targets/vuln-bank/clone.sh --dry-run
sh targets/vuln-bank/clone.sh
sh targets/vuln-bank/run.sh --dry-run
sh targets/vuln-bank/run.sh --execute --run-dir runs/pilot-vuln-bank-kali
```

`clone.sh` fetches the pinned commit `41c5b056f9ae8a8b15c77ea79f1419356b321634`
into `vendor/external/vuln-bank` (gitignored). `run.sh --execute` builds the
stack, publishes the web app on `127.0.0.1:5000` and the second mapping on
`127.0.0.1:8080`, waits for `/healthz`, plans `web-blackbox`, runs Nuclei and the
Playwright spec, imports Nuclei candidates, dedupes and renders the report.
Expected evidence:

```text
runs/pilot-vuln-bank-kali/scope.md
runs/pilot-vuln-bank-kali/threat-model.md
runs/pilot-vuln-bank-kali/checks.json
runs/pilot-vuln-bank-kali/plan.json
runs/pilot-vuln-bank-kali/logs/nuclei.log
runs/pilot-vuln-bank-kali/steps/nuclei.json
runs/pilot-vuln-bank-kali/findings/nuclei.json
runs/pilot-vuln-bank-kali/findings.json
runs/pilot-vuln-bank-kali/playwright-results.json
runs/pilot-vuln-bank-kali/playwright-stderr.log
runs/pilot-vuln-bank-kali/REPORT.md
runs/pilot-vuln-bank-kali/FINDINGS-DETAIL.md
runs/pilot-vuln-bank-kali/NEEDS-VALIDATION.md
```

## 4. Path B — Mac with `scripts/legion-tunnel.sh`

Use this path when the suite runs on macOS and the targets run on Legion. Each
forward maps a Legion loopback port to the same Mac loopback port:

```text
ssh -N -L 8080:127.0.0.1:8080 legion-ts
```

`8080` is replaced by `5000` for vuln-bank. The left and right port are always
the same number.

The tunnel script validates the port numbers and the host alias, never prompts
for a password and never uses `eval`:

```sh
sh scripts/legion-tunnel.sh --dry-run
sh scripts/legion-tunnel.sh --check
sh scripts/legion-tunnel.sh --execute 8080
```

`--check` is the only mode that contacts the host; it runs a bounded
`ssh -o BatchMode=yes legion-ts 'echo OK'`. Leave the `--execute` terminal open
and do the work in a second terminal. Run the tunnel on the Mac, not from
Windows into WSL: WSL-published loopback ports are not reachable from Windows or
another Tailscale node by default.

### 4.1 DVWA on the Mac

On Legion, start DVWA once (or leave the Kali run's container up):

```sh
docker compose -f targets/dvwa/compose.yaml up -d
```

On the Mac, terminal 1:

```sh
sh scripts/legion-tunnel.sh --execute 8080
```

Terminal 2:

```sh
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/
sh targets/dvwa/run.sh --no-compose --url http://127.0.0.1:8080 --run-dir runs/pilot-dvwa-mac
```

`--no-compose` keeps the Mac from starting a second container; `setup.sh` still
waits for the tunnel, resets the remote DVWA database and sets `security=low`
through the forwarded port. Evidence goes to `runs/pilot-dvwa-mac/` with the same
file list as the Kali cell.

### 4.2 vuln-bank on the Mac

On Legion, run the Kali sequence in section 3.2 to start the pinned lab. Leave it
running. On the Mac, terminal 1 forwards the web port:

```sh
sh scripts/legion-tunnel.sh --execute 5000
```

Terminal 2 checks readiness and runs the same pipeline steps individually:

```sh
curl -fsS http://127.0.0.1:5000/healthz
RUN=runs/pilot-vuln-bank-mac
mkdir -p "$RUN"
cat > "$RUN/scope.md" <<'SCOPE'
# Scope — vuln-bank Mac tunnel cell

## Allowed hosts
- http://127.0.0.1:5000

## Budget
- max_requests: 500
- max_seconds: 900

## Rules of engagement
- Authorized loopback lab reached through an SSH local forward from legion-ts.
- No brute force, denial of service or destructive writes.
SCOPE
uv run sak plan --suite web-blackbox --target http://127.0.0.1:5000 --run-dir "$RUN"
uv run sak run --run "$RUN" --step nuclei --execute
BASE_URL=http://127.0.0.1:5000 npx playwright test targets/vuln-bank/playwright/vuln-bank.spec.js --reporter=json > "$RUN/playwright-results.json" 2> "$RUN/playwright-stderr.log"
uv run sak findings import "$RUN/findings/nuclei.json" --run-dir "$RUN"
uv run sak findings dedupe --write "$RUN/findings.json"
uv run sak report "$RUN"
```

If `plan.json` does not contain a `nuclei` step, the binary or its templates are
missing. Run `uv run sak doctor`, install what it names, then re-run the plan
command before the Nuclei step.

Why not `sh targets/vuln-bank/run.sh --execute` on the Mac? The accepted harness
has no `--no-compose` flag, so `--execute` always starts a local compose stack
and would ignore the tunnel. The block above is the same sequence the harness
runs, with the local start removed. This gap is recorded as a docs question for
the senior; the acceptance row stays `lead-run` either way.

Expected evidence for this cell:

```text
runs/pilot-vuln-bank-mac/scope.md
runs/pilot-vuln-bank-mac/plan.json
runs/pilot-vuln-bank-mac/logs/nuclei.log
runs/pilot-vuln-bank-mac/steps/nuclei.json
runs/pilot-vuln-bank-mac/findings/nuclei.json
runs/pilot-vuln-bank-mac/findings.json
runs/pilot-vuln-bank-mac/playwright-results.json
runs/pilot-vuln-bank-mac/playwright-stderr.log
runs/pilot-vuln-bank-mac/REPORT.md
runs/pilot-vuln-bank-mac/FINDINGS-DETAIL.md
runs/pilot-vuln-bank-mac/NEEDS-VALIDATION.md
```

Close both tunnel terminals with `Ctrl-C` when the cell is done.

## 5. Playwright in the pilot flow

Playwright provides browser evidence, not a verdict.

### 5.1 DVWA scenario

`targets/dvwa/checks.json` is the scenario contract. It logs in, sets and
verifies `security=low`, visits the SQL injection and XSS pages and records page,
status and selected-text observations. Credentials use `${DVWA_USERNAME}` and
`${DVWA_PASSWORD}` substitution; the JSON stores only the variable names.

The harness injects the scenario path into the planned step. To run it alone
after a plan exists:

```sh
uv run sak run --run runs/pilot-dvwa-kali --step playwright --execute
```

A real run writes `logs/playwright.log`, `logs/playwright-result.json` and
`findings/playwright.json` inside the run. The runner records cookie names and
flags only, never values. `screenshot` and `save_storage_state` artifacts land
under `artifacts/playwright/`; a storage-state file does contain cookie values
and must stay out of git.

### 5.2 vuln-bank spec

The vuln-bank harness runs a standalone spec, `targets/vuln-bank/playwright/
vuln-bank.spec.js`, with two readiness checks: `/healthz` and the login page. It
does not log in or write data. Its JSON output stays in
`runs/pilot-vuln-bank-kali/playwright-results.json` and is not imported as
findings, because the spec reports readiness rather than a vulnerability claim.

## 6. Candidates, imported records and confirmed findings

Three different objects share the word "finding" in this pilot. Keep them apart:

| Stage | Where it lives | Status | Who can create it |
|---|---|---|---|
| Candidate | `runs/pilot-dvwa-kali/findings/nuclei.json`, `runs/pilot-dvwa-kali/findings/playwright.json` | raw observation, no schema id | adapter step |
| Imported record | `runs/pilot-dvwa-kali/findings.json` plus one `F-...-candidate.json` under `runs/pilot-dvwa-kali/evidence/` | `needs_validation` | `sak findings import` |
| Confirmed finding | `runs/pilot-dvwa-kali/findings.json`, status changed with evidence | `confirmed` | verifier via `sak findings status` |

Import never claims `confirmed`. It maps each candidate to a stable `F-*` id, a
schema-valid record, an open question and a next action, hashes a sanitized
evidence file and appends without duplicating an existing fingerprint.

Exact import commands for the pilot:

```sh
uv run sak findings import runs/pilot-dvwa-kali/findings/nuclei.json --run-dir runs/pilot-dvwa-kali --json
uv run sak findings import runs/pilot-dvwa-kali/findings/playwright.json --run-dir runs/pilot-dvwa-kali --json
uv run sak findings import runs/pilot-vuln-bank-kali/findings/nuclei.json --run-dir runs/pilot-vuln-bank-kali --json
uv run sak findings validate runs/pilot-dvwa-kali/findings.json
uv run sak findings dedupe --write runs/pilot-dvwa-kali/findings.json
uv run sak report runs/pilot-dvwa-kali
```

The import JSON reports `imported`, `skipped_duplicates`, `total` and the
`F-*` ids. A second import of the same file adds nothing. `sak findings validate`
is the schema and evidence-hash gate.

Promotion is a separate, evidence-backed step after a verifier replays the claim.
Write the replay output to the run's evidence directory first, then reference it:

```sh
uv run sak findings status F-031f45ee01c3d4c8 confirmed --run-dir runs/pilot-dvwa-kali --actor verifier --evidence runs/pilot-dvwa-kali/evidence/replay-request.txt --evidence-kind request --reason "replayed in a fresh session"
uv run sak findings status F-031f45ee01c3d4c8 rejected --run-dir runs/pilot-dvwa-kali --actor verifier --reason "not reproducible after two attempts"
uv run sak report runs/pilot-dvwa-kali
```

The id in the example is illustrative; use the id printed by
`uv run sak findings list runs/pilot-dvwa-kali/findings.json`. `confirmed` is refused
without at least one evidence record, and `needs_validation` is refused without
an open question and a next action. A rendered report counts the three verdicts
separately, so an imported candidate never inflates the confirmed count.

## 7. Failure handling

Each row is one symptom and the exact next command. Run the command from the
repository root unless it starts with `wsl.exe`.

| Symptom | Exact next command |
|---|---|
| Playwright refuses with a missing browser or Chromium | `npx playwright install chromium` then `uv run sak run --run runs/pilot-dvwa-kali --step playwright --execute` |
| `docker: command not found`, or `docker compose version` fails | `sh scripts/legion-tunnel.sh --execute 8080` then `sh targets/dvwa/run.sh --no-compose --url http://127.0.0.1:8080 --run-dir runs/pilot-dvwa-mac` |
| `curl` from Windows refuses `127.0.0.1:8080` while `ssh legion-ts` works | `wsl.exe -d kali-linux` then run `sh targets/dvwa/run.sh --run-dir runs/pilot-dvwa-kali` inside Kali |
| `port is already allocated` or a bind error on `8080` | `DVWA_PORT=8081 sh targets/dvwa/run.sh --url http://127.0.0.1:8081 --run-dir runs/pilot-dvwa-kali` |
| `port is already allocated` on vuln-bank `5000` | `sh targets/vuln-bank/run.sh --execute --target http://127.0.0.1:5001 --port 5001 --http-port 8081 --run-dir runs/pilot-vuln-bank-kali` |
| DVWA says the configured login was rejected | `docker compose -f targets/dvwa/compose.yaml down -v` then `docker compose -f targets/dvwa/compose.yaml up -d` then `sh targets/dvwa/setup.sh --url http://127.0.0.1:8080` |
| vuln-bank login fails after a database change | `(cd vendor/external/vuln-bank && docker compose down --volumes && docker compose up -d --build)` |
| The scan is empty: no `findings/nuclei.json` candidates, `imported: 0` | `uv run sak doctor` then `uv run sak run --run runs/pilot-dvwa-kali --step nuclei --execute` |
| `sak run --execute` refuses on budget | `uv run sak report runs/pilot-dvwa-kali` then re-plan into a fresh run directory only after the owner approves a wider scope |

Notes that keep the commands honest:

- An empty scan is a tool, scope or template problem until proven otherwise. It
  is not a clean target and not a finding.
- A budget refusal is a stop condition. Do not raise the budget by editing
  `scope.md` in place; re-plan with owner approval and keep the old run.
- A missing browser, Docker or Nuclei binary is an environment problem, not a
  target result.

## 8. Acceptance, evidence and cleanup

The matrix is [`targets/pilot/acceptance.md`](../targets/pilot/acceptance.md).
Four cells, all `lead-run`:

| Cell | Environment | Target | Run directory |
|---|---|---|---|
| DVWA / Kali | Kali WSL, local Docker | `http://127.0.0.1:8080` | `runs/pilot-dvwa-kali/` |
| DVWA / Mac tunnel | macOS, `scripts/legion-tunnel.sh` | `http://127.0.0.1:8080` | `runs/pilot-dvwa-mac/` |
| vuln-bank / Kali | Kali WSL, local Docker | `http://127.0.0.1:5000` | `runs/pilot-vuln-bank-kali/` |
| vuln-bank / Mac tunnel | macOS, `scripts/legion-tunnel.sh` | `http://127.0.0.1:5000` | `runs/pilot-vuln-bank-mac/` |

A cell passes only when the run directory contains `REPORT.md`,
`findings.json`, at least one step record and the expected evidence list from
the matrix — and `uv run sak findings validate` exits `0` on that
`findings.json`.

Cleanup after each cell:

```sh
docker compose -f targets/dvwa/compose.yaml down -v --remove-orphans
(cd vendor/external/vuln-bank && docker compose down --volumes)
uv run sak report runs/pilot-dvwa-kali
```

Stop the tunnel with `Ctrl-C`. Keep a run directory only if its evidence has no
session token, cookie value or raw credential; `sak` masks known secrets, but a
reviewed evidence file is still the operator's responsibility.

## 9. What remains unproven

- No live Docker start, browser run, SSH tunnel or imported live candidate was
  executed by the worker that wrote this page.
- The Mac vuln-bank cell depends on the manual block in section 4.2 because the
  accepted `targets/vuln-bank/run.sh` has no `--no-compose` mode.
- Nuclei template freshness, Playwright browser cache location and Docker
  networking differ per host; `uv run sak doctor` is the only supported check.
- Promotion to `confirmed` is a verifier action and has no automated test. The
  pilot proves the import and the refusal rules, not that any candidate is real.
