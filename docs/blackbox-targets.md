# Black-box target profiles

Two authorized loopback labs carry the black-box path: **DVWA at Low security** and
**vuln-bank**. This page is the operator and reviewer guide for their machine-readable
profiles, check sequences, accounts, scope, budget and expected-vulnerability rubric.

> **Authorized lab only.** Both targets are intentionally vulnerable. Bind them to
> `127.0.0.1`, reach them only through loopback or the owner's Legion/VPN tunnel, never load
> real data and never expose the ports to the internet.

## 1. Profiles and checks

| Target | Profile | Check sequences | Expected issues |
|---|---|---|---|
| DVWA (Low) | `targets/dvwa/blackbox/profile.yaml` | `targets/dvwa/blackbox/checks.json` | 11 (`DVWA-*`) |
| vuln-bank | `targets/vuln-bank/blackbox/profile.yaml` | `targets/vuln-bank/blackbox/checks.json` | 15 (`VB-*`) |

Each profile is parseable without target source. It records the target URL, accounts, auth
flow, CSRF and session handling, scope, budget, expected issues and safety. The companion
`checks.json` lists concrete HTTP/browser steps, the evidence each step must leave behind and
the cleanup for every sequence. Every expected issue id maps to exactly one check, so rubric
coverage and check coverage stay equal.

The run never reads target source, clones the target repository or inspects container files.
DVWA is used through its public login, security and vulnerability pages; vuln-bank is used
through the documented public routes already listed in `targets/vuln-bank/checks.json` and
`docs/targets/vuln-bank.md`. The vuln-bank upstream revision is recorded only as provenance
(`41c5b056f9ae8a8b15c77ea79f1419356b321634`); no source is read.

## 2. Targets, accounts and auth

### DVWA

| Field | Value |
|---|---|
| Base URL | `http://127.0.0.1:8080` (or `http://localhost:8080`) |
| Account | `admin` / documented demo password `password`, or `DVWA_PASSWORD` |
| Login | `POST /login.php` with `username`, `password`, `Login` and CSRF `user_token` |
| CSRF | Hidden `user_token` on each form; re-extract before every POST |
| Session | `PHPSESSID` cookie jar in an ignored run directory |
| Setup | `POST /security.php` with `security=low` and `seclev_submit=Submit` |
| Health | `GET /login.php` returns 200 and the DVWA login title |

DVWA credentials are documented demo defaults, not real secrets. The profile also names the
env override, so an operator can point at a differently configured lab without editing YAML.

### vuln-bank

| Field | Value |
|---|---|
| Base URL | `http://127.0.0.1:5000` (or `http://localhost:5000`) |
| Admin | `admin` / lab default `admin123`, account `ADMIN001` |
| Merchant | `bookstore@vulnbank.org` / lab default `bookstore123` |
| Testers | Register two run-created users through `POST /register` |
| Login | `POST /login` with `username` and `password`; response returns a JWT |
| Token | Response JSON `token` and browser `localStorage.token`; send as `Authorization: Bearer` |
| Session | Bearer JWT plus a secondary Flask session cookie |
| Health | `GET /healthz` returns `{"status":"ok","database":"up"}` |

Seeded merchant API keys stay in the lab database and are masked in evidence. Account
passwords and bearer tokens live only in ignored run files. The two run-created testers are
the only principals used for cross-account checks; seeded users are read-only targets.

## 3. Scope and budget

Both profiles are default-deny and require a `scope.md` before any active step.

| Target | Allowed hosts | Max requests | Max seconds | Max agents | Waves |
|---|---|---|---|---|---|
| DVWA | `127.0.0.1:8080`, `localhost:8080` | 400 | 900 | 2 | 2 |
| vuln-bank | `127.0.0.1:5000`, `localhost:5000` | 500 | 900 | 2 | 2 |

Out of scope for both: non-loopback hosts, internet-facing deployments, host Postgres port
`5432`, the vuln-bank `8080` HTTP mapping, seeded user/card state beyond documented reads,
real credentials, third-party data and denial of service. Stops are recorded in the profiles:
scope or account mismatch, an unapproved write, two waves without new signal, or any response
outside loopback.

Every confirmed finding needs observed evidence: a request/response pair, browser dialog or
trace, command output, an uploaded marker, a before/after state read, or a second-principal
read. Cookies, CSRF tokens, JWTs, passwords, password hashes and merchant keys are masked in
reports.

## 4. Kali-local path

Run Docker and the harness on the Kali host (the legion). No global tool install is done by
the harness.

```sh
cd /path/to/swiss-army-knife-skills

# DVWA: start, reset the lab DB, log in, set Low, smoke-test
sh targets/dvwa/setup.sh --url http://127.0.0.1:8080
sh targets/dvwa/run.sh --dry-run
sh targets/dvwa/run.sh --execute

# vuln-bank: pinned checkout, compose, health, smoke-test
sh targets/vuln-bank/clone.sh --dry-run
sh targets/vuln-bank/run.sh --dry-run
sh targets/vuln-bank/run.sh --execute
```

The base URLs match the profiles, so `sak` needs no host override on Kali. Health checks
bound startup: DVWA login page for DVWA, `/healthz` for vuln-bank. Stop DVWA with
`docker compose -f targets/dvwa/compose.yaml down`; stop vuln-bank with `docker compose down`
in its checkout, or add `--down` to the vuln-bank harness run.

## 5. Mac-tunnel path

Keep the target URLs loopback on the Mac and forward the lab ports over SSH. The profile
hosts stay unchanged, so the generated `scope.md` names only loopback.

```sh
# Option A: plain SSH local forwards
ssh -N -L 8080:127.0.0.1:8080 <owner-approved-legion-host>   # DVWA
ssh -N -L 5000:127.0.0.1:5000 <owner-approved-legion-host>   # vuln-bank

# Option B: the repo helper (prints commands unless --execute is passed)
sh scripts/legion-tunnel.sh --execute 8080
sh scripts/legion-tunnel.sh --execute 5000
```

Do not forward to `0.0.0.0`. If the lab is reached by a tunnel hostname instead of loopback,
that origin must be explicitly added to the profile scope and approved by the owner; the
default profiles stay loopback-only.

## 6. Expected-vulnerability rubric

### DVWA Low (11 expected issues)

| ID | Class | Endpoint | Severity | Intrusive | Proof |
|---|---|---|---|---|---|
| `DVWA-SQLI-01` | SQL injection | `GET /vulnerabilities/sqli/` | high | no | UNION or boolean differential returns user rows |
| `DVWA-CMDI-01` | Command injection | `POST /vulnerabilities/exec/` | high | yes | `127.0.0.1; id` returns `uid=` |
| `DVWA-UPLOAD-01` | Upload/RCE | `POST /vulnerabilities/upload/` | critical | yes | Benign PHP marker executes from `/hackable/uploads/` |
| `DVWA-XSS-R-01` | Reflected XSS | `GET /vulnerabilities/xss_r/` | medium | no | Payload reflected unencoded and fires |
| `DVWA-XSS-S-01` | Stored XSS | `POST /vulnerabilities/xss_s/` | high | yes | Marker payload executes in a fresh context |
| `DVWA-CSRF-01` | CSRF | `GET /vulnerabilities/csrf/` | high | yes | Tokenless password change, then restore |
| `DVWA-FI-01` | File inclusion | `GET /vulnerabilities/fi/` | high | no | Traversal returns `root:x:0:0` |
| `DVWA-BRUTE-01` | Brute force | `GET /vulnerabilities/brute/` | medium | yes | Valid lab password reached within 10 requests, no lockout |
| `DVWA-SESSION-01` | Weak session ids | `GET /vulnerabilities/weak_id/` | medium | no | `dvwaSession` increments predictably |
| `DVWA-CSP-01` | CSP bypass | `GET /vulnerabilities/csp/` | medium | no | Inline script executes despite the CSP header |
| `DVWA-CAPTCHA-01` | CAPTCHA bypass | `POST /vulnerabilities/captcha/` | medium | yes | Password changes without a fresh challenge, then restore |

### vuln-bank (15 expected issues)

| ID | Class | Endpoint | Severity | Intrusive | Proof |
|---|---|---|---|---|---|
| `VB-AUTH-01` | Authentication / SQLi login | `POST /login` | critical | yes | Boolean login payload returns a token or DB error |
| `VB-AUTH-02` | Authentication / JWT | `GET /dashboard` | high | no | Tampered `is_admin` or `user_id` accepted |
| `VB-BOLA-01` | IDOR | `GET /transactions/<account>` | high | no | Tester B reads ADMIN001 or tester A |
| `VB-BOLA-02` | IDOR | `GET /api/virtual-cards/<id>` | high | yes | Non-owner reads a run-created card |
| `VB-BOPLA-01` | Authorization / mass assignment | `POST /update_bio` | high | yes | Extra `is_admin`/`balance` fields persist |
| `VB-SQLI-01` | SQL injection | `POST /api/bill-payments/create` | critical | yes | Quoted biller id causes error or differential |
| `VB-XSS-01` | Stored XSS | `POST /update_bio` | high | yes | Bio payload executes in a fresh context |
| `VB-NEG-01` | Business logic | `POST /transfer` | critical | yes | Negative amount credits the sender |
| `VB-CARD-01` | Business logic | `POST /api/virtual-cards/<id>/fund` | high | yes | Client rate over-credits the card |
| `VB-MERCH-01` | Business logic | `POST /api/v1/payments/charge` | high | yes | Replayed order id or negative amount accepted |
| `VB-GQL-01` | Admin privilege | `POST /graphql` | high | no | Introspection plus admin analytics on a low-priv token |
| `VB-SSRF-01` | SSRF | `POST /upload_profile_picture_url` | critical | yes | Loopback internal document fetched |
| `VB-UPLOAD-01` | Unrestricted upload | `POST /upload_profile_picture` | high | yes | Text file accepted and served |
| `VB-INFO-01` | Information disclosure | `GET /.env` | high | no | Config or debug users returned unauthenticated |
| `VB-AI-01` | Prompt injection | `POST /api/ai/chat/anonymous` | high | yes | Assistant discloses data or instructions |

Every entry carries a class, endpoint, proof condition, severity, `intrusive` flag and
cleanup in the profile; every check carries ordered steps and expected evidence in
`checks.json`. Intrusive checks are pre-approved by the profile because both targets are
authorized disposable labs. Brute force is the exception: `DVWA-BRUTE-01` is disabled by
default and needs explicit owner approval. No check is destructive. Cleanup removes only
lab-created markers, files, rows, cards, bills and temporary password changes, then verifies
the restored state.

## 7. Why “all vulnerabilities” means the rubric

No black-box run can prove the absence of every possible bug. DVWA exposes more pages across
security levels than the Low profile exercises, and vuln-bank has additional API, GraphQL, LLM
and merchant surfaces beyond the 15 listed checks. “All vulnerabilities” in a `sak` report
therefore means **all expected issues in this rubric**, not a literal claim about the universe
of possible defects:

- the denominator is the profile's `expected` list — 11 for DVWA Low and 15 for vuln-bank;
- coverage counts an issue only when its check ran and left the named evidence;
- `confirmed` requires observed proof, not a tool signature or a guess;
- `needs_validation` and `rejected` remain visible and count against clean coverage;
- findings outside the rubric are reported separately as extras and never silently expand the
  denominator.

Reports should state the target, profile path, expected count, confirmed/needs-validation/
rejected counts and any unrun checks. A rubric result of “11/11 confirmed” means the expected
list was fully evidenced; it does not mean the application is free of other bugs.

## 8. Handoff to the black-box commands

The profiles and checks are consumed by the pack's `sak hunt`, `sak exploit` and `sak verify`
interfaces (X2–X4). A reviewer can validate them offline today:

```sh
uv run pytest tests/test_blackbox_profiles.py -q
python3 -c "import yaml,json; yaml.safe_load(open('targets/dvwa/blackbox/profile.yaml')); yaml.safe_load(open('targets/vuln-bank/blackbox/profile.yaml'))"
```

Live execution stays a lead-run acceptance action after the harness and offline tests pass.
Evidence must be ingested before cleanup, and run directories stay until the black-box report
is accepted.
