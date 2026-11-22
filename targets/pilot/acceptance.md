# Pilot acceptance matrix

Four live cells cover both targets in both environments. Every cell is
**`lead-run`**: the lead executes it after merge and records the outcome here.
No cell is claimed by a worker, and no live result exists at the time of writing.

- Runbook: [`docs/pilot.md`](../../docs/pilot.md)
- Target index: [`README.md`](README.md)
- Harness owners: T3 (DVWA), T4 (vuln-bank), T5 (tunnel), T1 (Playwright), T2
  (findings import)

## Matrix

| Cell | Environment | Target | Runner | Budget | Status |
|---|---|---|---|---|---|
| DVWA / Kali | Kali WSL, local Docker | `http://127.0.0.1:8080` | `lead` | 500 requests, 300 seconds | `lead-run` |
| DVWA / Mac tunnel | macOS, `scripts/legion-tunnel.sh` | `http://127.0.0.1:8080` | `lead` | 500 requests, 300 seconds | `lead-run` |
| vuln-bank / Kali | Kali WSL, local Docker | `http://127.0.0.1:5000` | `lead` | 500 requests, 900 seconds | `lead-run` |
| vuln-bank / Mac tunnel | macOS, `scripts/legion-tunnel.sh` | `http://127.0.0.1:5000` | `lead` | 500 requests, 900 seconds | `lead-run` |

A cell passes only when all of these hold on the lead's host:

1. the named run command exits `0`;
2. the run directory contains every path in the cell's evidence list below;
3. `uv run sak findings validate` exits `0` on the run's `findings.json`;
4. the rendered `REPORT.md` shows `needs_validation` records and no unverified
   `confirmed` count;
5. the operator confirms no credential, session token or cookie value appears in
   the evidence.

## DVWA / Kali

- Run directory: `runs/pilot-dvwa-kali/`
- Runner: `lead`, inside Kali WSL
- Preconditions: Docker Compose v2 in Kali, `uv sync`, `nuclei`, Node with
  Playwright and Chromium, `targets/dvwa/.env` copied from `.env.example`
- Command:

```sh
sh targets/dvwa/run.sh --run-dir runs/pilot-dvwa-kali
```

- Exact evidence paths:

```text
runs/pilot-dvwa-kali/scope.md
runs/pilot-dvwa-kali/threat-model.md
runs/pilot-dvwa-kali/plan.json
runs/pilot-dvwa-kali/logs/nuclei.log
runs/pilot-dvwa-kali/logs/playwright.log
runs/pilot-dvwa-kali/logs/playwright-result.json
runs/pilot-dvwa-kali/steps/nuclei.json
runs/pilot-dvwa-kali/steps/playwright.json
runs/pilot-dvwa-kali/findings/nuclei.json
runs/pilot-dvwa-kali/findings/playwright.json
runs/pilot-dvwa-kali/findings.json
runs/pilot-dvwa-kali/evidence/
runs/pilot-dvwa-kali/REPORT.md
runs/pilot-dvwa-kali/FINDINGS-DETAIL.md
runs/pilot-dvwa-kali/NEEDS-VALIDATION.md
```

- Expected signal: setup reports database reset, login and `security=low`;
  Nuclei and Playwright step records have `returncode: 0`; `findings.json` has
  at least one `needs_validation` record or an explicit empty-scan note.

## DVWA / Mac tunnel

- Run directory: `runs/pilot-dvwa-mac/`
- Runner: `lead`, on macOS
- Preconditions: DVWA running on Legion at loopback `8080`; `ssh legion-ts
  'echo OK'` succeeds; Playwright and Chromium installed on the Mac
- Command, terminal 1:

```sh
sh scripts/legion-tunnel.sh --execute 8080
```

- Command, terminal 2:

```sh
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/
sh targets/dvwa/run.sh --no-compose --url http://127.0.0.1:8080 --run-dir runs/pilot-dvwa-mac
```

- Exact evidence paths:

```text
runs/pilot-dvwa-mac/scope.md
runs/pilot-dvwa-mac/threat-model.md
runs/pilot-dvwa-mac/plan.json
runs/pilot-dvwa-mac/logs/nuclei.log
runs/pilot-dvwa-mac/logs/playwright.log
runs/pilot-dvwa-mac/logs/playwright-result.json
runs/pilot-dvwa-mac/steps/nuclei.json
runs/pilot-dvwa-mac/steps/playwright.json
runs/pilot-dvwa-mac/findings/nuclei.json
runs/pilot-dvwa-mac/findings/playwright.json
runs/pilot-dvwa-mac/findings.json
runs/pilot-dvwa-mac/evidence/
runs/pilot-dvwa-mac/REPORT.md
runs/pilot-dvwa-mac/FINDINGS-DETAIL.md
runs/pilot-dvwa-mac/NEEDS-VALIDATION.md
```

- Expected signal: same as the Kali cell, with scope still naming only
  `http://127.0.0.1:8080` and the tunnel command in the run notes.

## vuln-bank / Kali

- Run directory: `runs/pilot-vuln-bank-kali/`
- Runner: `lead`, inside Kali WSL
- Preconditions: pinned checkout from `clone.sh`, Docker Compose v2, `uv sync`,
  `nuclei`, Node with Playwright and Chromium, health at `/healthz`
- Commands:

```sh
sh targets/vuln-bank/clone.sh
sh targets/vuln-bank/run.sh --execute --run-dir runs/pilot-vuln-bank-kali
```

- Exact evidence paths:

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

- Expected signal: `run.sh` verifies the pinned commit, `/healthz` becomes ready,
  the Nuclei step record has `returncode: 0`, the Playwright spec reports two
  passing readiness checks, and the report renders the imported candidates as
  `needs_validation`.

## vuln-bank / Mac tunnel

- Run directory: `runs/pilot-vuln-bank-mac/`
- Runner: `lead`, on macOS
- Preconditions: the pinned lab is already running on Legion at loopback `5000`;
  `ssh legion-ts 'echo OK'` succeeds; `nuclei`, Node, Playwright and Chromium are
  installed on the Mac
- Command, terminal 1:

```sh
sh scripts/legion-tunnel.sh --execute 5000
```

- Command, terminal 2: the manual pipeline block in
  [`docs/pilot.md`](../../docs/pilot.md) section 4.2. It writes `scope.md`,
  plans `web-blackbox`, runs the Nuclei step, runs the Playwright spec, imports
  and dedupes candidates and renders the report.
- Why manual: the accepted `targets/vuln-bank/run.sh` has no `--no-compose` mode,
  so `--execute` would start a local stack and ignore the tunnel. The gap is
  recorded in `docs/pilot.md`; the cell remains valid because it runs the same
  pipeline steps against the tunneled loopback target.
- Exact evidence paths:

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

- Expected signal: `/healthz` returns 200 through the tunnel, the scope allowlist
  names only `http://127.0.0.1:5000`, and the report renders the same shape as
  the Kali cell. `threat-model.md` is not produced on this manual path.

## Result log

The lead records one row per executed cell. Leave a row empty until it runs; do
not pre-fill a verdict.

| Cell | Run at (UTC) | Command exit | Findings imported | Confirmed | Verdict | Notes |
|---|---|---|---|---|---|---|
| DVWA / Kali | | | | | | |
| DVWA / Mac tunnel | | | | | | |
| vuln-bank / Kali | | | | | | |
| vuln-bank / Mac tunnel | | | | | | |

## Cross-cell checks

After all four cells, the lead also confirms:

- `uv run sak catalog validate` still exits `0` and the catalog is unchanged by
  a run;
- no `runs/` directory, `.env`, `vendor/external/` checkout or Playwright
  artifact is staged for commit;
- every `REPORT.md` was rendered after the last `findings.json` change;
- a fresh `uv run pytest -q` on the merged `main` still passes the offline
  suites.
