# vuln-bank target guide

Operator guide for the `vuln-bank` harness in [`targets/vuln-bank/`](../../targets/vuln-bank/README.md).
It covers the pinned upstream, both runtime paths (Kali-local and Mac tunnel), ports,
accounts, scope, expected evidence and cleanup.

> **Warning:** vuln-bank is intentionally vulnerable. It runs a Flask dev server in debug
> mode and stores passwords in plaintext. Use loopback Docker or an owner-approved
> Legion/VPN tunnel only. Never expose it to the internet, never load real data, and never
> leave it running after the assessment.

## 1. Upstream and pinned revision

| Field | Value |
|---|---|
| Repository | <https://github.com/Commando-X/vuln-bank> |
| Clone URL | `https://github.com/Commando-X/vuln-bank.git` |
| Default branch | `main` |
| Pinned commit | `41c5b056f9ae8a8b15c77ea79f1419356b321634` |
| Pin date | 2026-11-04 |
| License | MIT (`LICENSE.md` upstream) |
| Local checkout | `vendor/external/vuln-bank` (gitignored, never vendored) |
| Compose file | `docker-compose.yml` |
| Startup (upstream) | `docker-compose up -d --build` |

`clone.sh` is the only supported way to obtain the source. It clones `main`, checks out the
pinned commit, verifies the checkout hash, the compose file, the four services, the three
ports and the MIT license, then prints the next command. It refuses to touch an existing
checkout unless `--reuse` is passed, and `--reuse` only verifies. Nothing is deleted or
reset by the harness.

```sh
sh targets/vuln-bank/clone.sh --dry-run   # offline; prints the exact commands
sh targets/vuln-bank/clone.sh             # network clone into vendor/external/vuln-bank
sh targets/vuln-bank/clone.sh --reuse     # verify an existing checkout
```

## 2. Services and ports

| Service | Image | Host port (upstream default) | Harness default | Purpose |
|---|---|---|---|---|
| `web` | built from `Dockerfile` | `5000` (`VULNBANK_WEB_PORT`) | `127.0.0.1:5000` | Flask app, API and GraphQL |
| `web` | same | `80` (`VULNBANK_HTTP_PORT`) | `127.0.0.1:8080` | Second mapping to the same app |
| `db` | `postgres:13` | `5432` | `5432` (upstream-pinned) | Lab database |
| `xss-cleaner` | built from `Dockerfile` | none | none | Neutralizes stored XSS after 15 minutes |
| `autoheal` | `willfarrell/autoheal:latest` | none | none | Restarts unhealthy containers via `docker.sock` |

Health: `GET /healthz` returns `{"status":"ok","database":"up"}` with HTTP 200 only when
Postgres is reachable. The harness polls it for up to `--timeout` seconds (default 180).

The harness starts compose with:

```sh
VULNBANK_WEB_PORT=127.0.0.1:5000 \
VULNBANK_HTTP_PORT=127.0.0.1:8080 \
docker compose up -d --build
```

That publishes both web mappings on loopback only. `VULNBANK_WEB_PORT` and
`VULNBANK_HTTP_PORT` accept the `IP:port` short syntax because the compose file
interpolates them directly into the `ports` list.

> **Known limitation:** `db` pins `5432:5432` without a host address, so Docker publishes
> it on all interfaces. The harness does not edit the external checkout to change that.
> Run the lab on an isolated host/VPN, block 5432 at the host firewall, and stop any local
> Postgres that already owns 5432 before starting. The harness never connects to 5432.

## 3. Prerequisites

| Tool | Why | Check |
|---|---|---|
| Docker + Compose v2 | run the lab | `docker compose version` |
| `uv` | run `sak` | `uv run sak --version` |
| `git` | pinned checkout | `git --version` |
| `curl` | readiness and scenario requests | `curl --version` |
| `nuclei` | black-box scanning through the adapter | `uv run sak doctor` |
| Node + `npx` + Playwright | browser evidence | `npx playwright --version` |

Playwright browsers and Node packages are installed by the operator
(`npm install --save-dev @playwright/test && npx playwright install chromium`) and are never
committed. Nuclei templates are prepared by the operator; the adapter never updates them.
Missing tools are reported by `sak doctor`, not installed by the harness.

## 4. Kali-local path

Run everything on the Kali host (the legion).

```sh
cd /path/to/swiss-army-knife-skills
sh targets/vuln-bank/clone.sh --dry-run
sh targets/vuln-bank/clone.sh
sh targets/vuln-bank/run.sh --dry-run
sh targets/vuln-bank/run.sh --execute
```

`run.sh --execute`:

1. verifies the checkout is at the pinned commit;
2. starts compose with loopback port overrides;
3. waits for `/healthz`;
4. writes `scope.md` and `threat-model.md` and copies `checks.json` into the run directory;
5. runs `sak plan --suite web-blackbox --target http://127.0.0.1:5000 --run-dir <run>`;
6. runs the planned `nuclei` step with `sak run --execute` (scope and budget gate);
7. runs the Playwright smoke spec with `BASE_URL` set to the target;
8. imports `findings/nuclei.json`, dedupes and renders `sak report` (`REPORT.md`,
   `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`).

The lab stays up at the end so the operator can continue with manual scenarios. Stop it
with `(cd vendor/external/vuln-bank && docker compose down)`.

## 5. Mac tunnel path

Use this when the lab runs on Kali and the operator works from a Mac. There are two
shapes; both keep the assessment on loopback or an owner-approved tunnel.

### A. SSH local forward (harness on the Mac)

```sh
# Terminal 1: forward a local port to the lab on the Kali host
ssh -N -L 5000:127.0.0.1:5000 <owner-approved-legion-host>

# Terminal 2: harness keeps the loopback default
sh targets/vuln-bank/run.sh --dry-run
sh targets/vuln-bank/run.sh --execute
```

The target stays `http://127.0.0.1:5000` from the Mac's point of view, so `scope.md`
contains only loopback hosts. The SSH connection is the only route to the lab; do not
forward the port to `0.0.0.0`.

### B. Tunnel origin (harness reaches the lab by name)

```sh
sh targets/vuln-bank/run.sh --execute --tunnel-url http://<legion-host>:5000
```

`run.sh` refuses any non-loopback target unless `--tunnel-url` is present and exactly
equals the target origin, then writes that host into `scope.md`. Example origins are the
owner's Tailscale MagicDNS name or an SSH-forwarded host alias; the value must come from
the owner, not from the upstream README.

## 6. Test accounts

The database seeds one admin and three merchants on first start. These are lab-only
defaults; register additional users through `/register` for two-principal tests.

| Role | Username / email | Password | Notes |
|---|---|---|---|
| Admin | `admin` | `admin123` | Account `ADMIN001`, balance 1,000,000, `is_admin=true` |
| Merchant | `bookstore@vulnbank.org` | `bookstore123` | Seeded merchant with an API key in the lab database |
| Merchant | `pwnshop@vulnbank.org` | `pwnshop123` | Seeded merchant |
| Merchant | `zerohealth@vulnbank.org` | `zerohealth123` | Seeded merchant |
| Tester A / B | register at `/register` | your choice | Use two accounts for BOLA/BOPLA comparisons |

Do not copy merchant API keys into notes, reports or commits; retrieve them from the lab
database only when a scenario needs one, and mask them in evidence. The upstream `.env`
contains placeholder values only; never commit a real `.env`.

## 7. Scope

`run.sh` generates `scope.md` from the target and the budget. `targets/vuln-bank/scope.example.md`
shows the reviewed template. The rules:

- Positive list only: the generated `## Allowed hosts` entry is the sole authorized host.
- Budget: `max_requests: 500`, `max_seconds: 900`; `sak run --execute` enforces them.
- Writes are serialized, need owner approval and must record the account pair, object id
  and expected state change.
- The PIN brute-force scenario is disabled by default and must be opened explicitly in
  scope with a request cap.
- Stored payloads are benign and cleaned within 15 minutes by `xss-cleaner`.
- Stop on scope or account mismatch, an unapproved write, a destructive request, or two
  consecutive waves without new signal.

## 8. Scenario map

`checks.json` is the machine-readable list; this is the operator summary. All ids are
stable and referenced by the threat model.

| ID | Area | Endpoint | Severity | Approval | Tool |
|---|---|---|---|---|---|
| `VB-AUTH-01` | SQL injection in login | `POST /login` | critical | yes (write) | curl |
| `VB-AUTH-02` | Tampered JWT claims | `GET /dashboard` | high | no | playwright |
| `VB-AUTH-03` | 3-digit reset PIN | `POST /reset-password` | high | yes, disabled | manual |
| `VB-BOLA-01` | Other users' transactions | `GET /transactions/<account>` | high | no | curl |
| `VB-BOLA-02` | Virtual card BOLA | `GET /api/virtual-cards/<id>` | high | yes (write) | curl |
| `VB-BOPLA-01` | Mass assignment on profile | `POST /update_bio` | high | yes (write) | curl |
| `VB-SQLI-01` | Biller SQL injection | `POST /api/bill-payments/create` | critical | yes (write) | curl |
| `VB-GQL-01` | GraphQL introspection | `POST /graphql` | high | yes (write) | curl |
| `VB-SSRF-01` | Profile image SSRF | `POST /upload_profile_picture_url` | critical | yes (write) | curl |
| `VB-UPLOAD-01` | Unrestricted upload | `POST /upload_profile_picture` | high | yes (write) | curl |
| `VB-XSS-01` | Stored XSS in bio | `POST /update_bio` | high | yes (write) | playwright |
| `VB-NEG-01` | Negative transfer | `POST /transfer` | critical | yes (write) | curl |
| `VB-CARD-01` | Client-controlled rate | `POST /api/virtual-cards/<id>/fund` | high | yes (write) | curl |
| `VB-MERCH-01` | Charge replay | `POST /api/v1/payments/charge` | high | yes (write) | curl |
| `VB-AI-01` | Prompt injection | `POST /api/ai/chat/anonymous` | high | yes (write) | curl |
| `VB-INFO-01` | Exposed config/debug | `GET /.env` | high | no | nuclei |

The AI chat runs in mock mode unless `DEEPSEEK_API_KEY` is set; never set a real key for
this lab. GraphQL lives at `/graphql`, API docs at `/api/docs`, and the internal SSRF
targets at `/internal/secret`, `/internal/config.json` and `/latest/meta-data/...`.

## 9. Expected evidence

Collect, per scenario, the artifact named in `checks.json`:

- the request and the full response (headers plus masked body) or a Playwright trace;
- the principal used and the object id for authorization claims;
- a before/after read for balance, card and transaction state changes;
- a fresh replay from a second context for every `confirmed` claim;
- the exact upstream revision in the report metadata.

The Nuclei adapter writes sanitized candidates to `findings/nuclei.json`; Playwright writes
`playwright-results.json`. Raw captures, cookies, API keys and tokens never enter the run
directory, logs, findings or report. Mask authorization headers and any secret-shaped
value before saving evidence.

## 10. Verify and report

```sh
uv run sak findings list runs/vuln-bank-<UTC>/findings.json
uv run sak findings validate runs/vuln-bank-<UTC>/findings.json
uv run sak report runs/vuln-bank-<UTC>
```

Candidate findings start as `needs_validation`. A verifier re-derives each claim from
evidence, prefers a different principal and path, and records `confirmed`,
`needs_validation` or `rejected`. `sak report` warns when `coverage-ledger.json` is missing;
record boundary coverage before treating the report as complete.

## 11. Stop and cleanup

```sh
# stop the lab, keep the database volume
(cd vendor/external/vuln-bank && docker compose down)

# stop and reset the lab database (destroys lab data only)
(cd vendor/external/vuln-bank && docker compose down --volumes)

# or through the harness
sh targets/vuln-bank/run.sh --execute --down
sh targets/vuln-bank/run.sh --execute --down --purge
```

The harness does not delete the checkout. Remove `vendor/external/vuln-bank` manually if
the pin must be re-fetched, and close any SSH forward or tunnel when finished. Revoke
merchant keys and discard lab cookies/tokens after the assessment.

## 12. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `checkout already exists` | `clone.sh` refuses to overwrite. Use `--reuse` to verify, or remove the directory manually. |
| `checkout is at <sha>` | The external checkout drifted. Re-fetch the pinned commit; do not edit vendored files. |
| `healthz did not become ready` | Compose logs are printed. Check Postgres health, port conflicts and the 5432 limitation. |
| Port 5000 already in use | Re-run with `--port 5001`; the target default only follows `--target`. |
| Port 80 needs privileges | The harness moves the second mapping to 8080; override with `--http-port`. |
| Playwright skipped | Install `@playwright/test` and browsers, and keep `npx` on `PATH`. |
| Nuclei skipped | `sak plan` did not include it, or the binary is missing. Run `uv run sak doctor`. |
| AI chat gives mock answers | Expected without `DEEPSEEK_API_KEY`; the mock path is the safe lab default. |
| Stored XSS disappears | `xss-cleaner` neutralizes payloads after 15 minutes; re-seed for another window. |
| `autoheal` fails to start | It mounts `docker.sock`; on rootless or remote Docker it may need to be stopped. |

## 13. Limitations and non-goals

- No upstream source is vendored, mirrored or modified by this repository.
- No live Docker, network or browser execution in tests; tests are offline and dry-run only.
- The harness does not write a coverage ledger or confirm findings; those remain verifier
  actions.
- The upstream Postgres publication on 5432 cannot be made loopback-only without editing
  the external checkout.
- The lab is not hardened and must not be reused as a template for a real service.
