# Black-box pilot — DVWA Low and vuln-bank

This is the operator record for the `sak-blackbox-pack-v1` live pilot. It covers the
loopback lab targets only: DVWA at Low security and the pinned vuln-bank lab. The
target source was not read; every proof comes from HTTP requests, served pages, JSON
responses and the profile rubrics.

The denominator is the target profile's `expected` rubric, not "every possible
vulnerability". A 15/15 or 11/11 result means every intended issue in that rubric was
covered by a bounded check with evidence. It does not claim that the application has
no other weaknesses.

## 1. What "break into" means here

The pilot proves **authorization and input-handling boundary crossings**, not a
persistent shell or a production compromise:

- read another principal's object or admin data with a low-privilege session;
- change server-side state that the client should not control;
- execute a benign marker through an upload or command-injection surface;
- recover lab secrets from an unauthenticated endpoint;
- prove a JWT or session decision can be forged in the lab.

Every confirmed record carries the request/response evidence that proves the rubric
condition. A check that only observed a denial, a timeout or an unsupported action is
reported as `rejected`, `needs_validation` or `deferred`, never as confirmed.

## 2. Prerequisites

| Requirement | Used for | Check |
|---|---|---|
| `uv` with a synced checkout | every `sak` command | `uv sync` |
| Docker on the remote lab host | DVWA and vuln-bank containers | `docker ps` on the lab host |
| SSH access to `sak-lab` | Mac tunnel path | `ssh sak-lab 'echo OK'` |
| `curl` | readiness and DVWA setup | `curl --version` |
| `NEAR_AI_API_KEY` in the environment | `sak hunt` only | `test -n "$NEAR_AI_API_KEY"` |
| The profile accounts | authenticated checks | labels only; do not print the credentials |

The DVWA and vuln-bank containers are lab-only. Do not point these commands at an
internet-facing host. Active checks require the run's `scope.md`; the profile also
enforces a loopback host allowlist.

The vuln-bank lab is mapped to `127.0.0.1:5000` on the Docker host. On macOS,
port `5000` is commonly occupied by AirTunes, so the pilot uses
`127.0.0.1:15000` through an SSH tunnel. DVWA uses `127.0.0.1:8080`.

## 3. Kali WSL path

Use this path when `sak`, Docker and both targets run inside the same Kali WSL
distribution. No tunnel is needed.

```sh
docker ps
curl -fsS http://127.0.0.1:5000/healthz
curl -fsS -o /dev/null http://127.0.0.1:8080/login.php

uv run sak exploit \
  --run runs/blackbox-vuln-bank-final \
  --target http://127.0.0.1:5000 \
  --profile targets/vuln-bank/blackbox/profile.yaml \
  --json > runs/blackbox-vuln-bank-final/exploit.json

uv run sak exploit \
  --run runs/blackbox-dvwa-final \
  --target http://127.0.0.1:8080 \
  --profile targets/dvwa/blackbox/profile.yaml \
  --json > runs/blackbox-dvwa-final/exploit.json
```

Create a `scope.md` in each run directory before the first live request. The run
directory is the evidence boundary; start `sak hunt` from a scratch directory so
child downloads and temporary bodies stay under `runs/`, not the repository root.

## 4. Mac SSH-tunnel path

Use this path when the targets run on a remote lab host and `sak` runs on the Mac.
Keep the forwards alive with keepalives; an idle forward can be closed by the
network. Replace `sak-lab` below with your SSH alias or Tailscale MagicDNS name.

```sh
ssh -N -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
  -L 15000:127.0.0.1:5000 sak-lab

ssh -N -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
  -L 8080:127.0.0.1:8080 sak-lab
```

Verify both paths before a run:

```sh
curl -fsS http://127.0.0.1:15000/healthz
curl -fsS -o /dev/null http://127.0.0.1:8080/login.php
```

Then run the same `sak exploit` commands with the tunneled bases:

```sh
uv run sak exploit \
  --run runs/blackbox-vuln-bank-final \
  --target http://127.0.0.1:15000 \
  --profile targets/vuln-bank/blackbox/profile.yaml --json

uv run sak exploit \
  --run runs/blackbox-dvwa-final \
  --target http://127.0.0.1:8080 \
  --profile targets/dvwa/blackbox/profile.yaml --json
```

The vuln-bank profile allows both ports in `scope.allowed_hosts`. Use `5000` on Kali
and `15000` on the Mac; never use the Mac's AirTunes service on `5000`.

## 5. DVWA setup

DVWA must be started and set to Low before the checks. The login form and the
security page both carry a CSRF token; the profile login fields and the security
setup contract live in `targets/dvwa/blackbox/profile.yaml`.

1. Open `http://127.0.0.1:8080/login.php` and sign in with the documented demo
   account.
2. Open `http://127.0.0.1:8080/security.php`, choose `low`, and submit.
3. Confirm the page reports the Low level selected.

The pilot's checks include two password-changing proofs (CSRF and CAPTCHA). Both
restore the original demo password and finish with a fresh login. If a check is
interrupted mid-sequence, restore the password with the CSRF page before running the
next cell.

## 6. Exact command matrix

Run from the repository root. The examples use the Mac tunnel; substitute `5000` for
the Kali path.

```sh
# 1. Hunt (optional signal; needs the model key)
NEAR_AI_API_KEY="$NEAR_AI_API_KEY" \
SAK_HUNT_ACCOUNT="dvwa-admin (see profile)" \
uv run sak hunt \
  --run runs/blackbox-dvwa-hunt \
  --target http://127.0.0.1:8080 \
  --prompts INV-01 --max-agents 1 --timeout 180 --json

# 2. Exploit proofs
uv run sak exploit --run runs/blackbox-vuln-bank-final \
  --target http://127.0.0.1:15000 \
  --profile targets/vuln-bank/blackbox/profile.yaml --json

uv run sak exploit --run runs/blackbox-dvwa-final \
  --target http://127.0.0.1:8080 \
  --profile targets/dvwa/blackbox/profile.yaml --json

# 3. Rubric verification (read-only with respect to the source evidence)
uv run sak verify --run runs/blackbox-vuln-bank-final \
  --profile targets/vuln-bank/blackbox/profile.yaml --json

uv run sak verify --run runs/blackbox-dvwa-final \
  --profile targets/dvwa/blackbox/profile.yaml --json

# 4. Rendered report (requires findings.json and coverage-ledger.json)
uv run sak report runs/blackbox-vuln-bank-final
uv run sak report runs/blackbox-dvwa-final
```

`sak verify` is the scoring gate: it maps every exploit record to the rubric and
writes `verify.json`, `VERIFICATION.md` and `verified-findings.json`. `sak report`
is the reviewer-facing renderer for the confirmed findings, the coverage ledger and
the needs-validation list. The pilot generated both from the confirmed artifacts so
the report does not render zero findings.

## 7. Evidence to expect

Each run directory keeps the source evidence; `sak verify` and `sak report` only add
derived files.

| File | Meaning |
|---|---|
| `scope.md` | Allowed hosts, exclusions and budget for the run |
| `exploit/*.json` | One sanitized artifact per check, with request/response evidence and a proof flag |
| `hunt/*.json` | Hunter candidates and their `needs_validation` status |
| `verify.json` | Machine-readable rubric table and coverage counts |
| `VERIFICATION.md` | Reviewer-facing proof and coverage statement |
| `findings.json` | Confirmed findings derived from the verified artifacts |
| `coverage-ledger.json` | Boundary-to-probe coverage |
| `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md` | Rendered report set |
| `run-metadata.json` | Target, scope, revision and operator labels |

Cookies, bearer tokens, passwords, merchant keys, environment values, card numbers
and CVVs are masked in the artifacts. The evidence files stay under `runs/` and are
kept after the pilot.

## 8. What was proven

Live run on 2026-11-22 against the remote lab host:

| Target | Rubric | Confirmed | Coverage | Evidence |
|---|---|---|---|---|
| vuln-bank | 15 expected | 15 | 15/15 covered, ratio 1.0 | `runs/blackbox-vuln-bank-final/` |
| DVWA Low | 11 expected | 11 | 11/11 covered, ratio 1.0 | `runs/blackbox-dvwa-final/` |

The vuln-bank checks confirmed: login SQL injection, JWT claim forgery from the
exposed signing secret, transaction and virtual-card object-level access, mass
assignment on registration, bill-payment SQL injection, stored bio/admin-view XSS,
negative transfer, client-controlled card funding rate, merchant order replay and a
negative charge, GraphQL introspection under a low-privilege token, SSRF to the
loopback internal document, unrestricted profile upload, exposed environment/debug
endpoints, and prompt injection in the support chat.

The durable benchmark record, per-issue artifacts and interpretation rules are in
[benchmark.md](benchmark.md) and `benchmarks/*.json`.

The DVWA checks confirmed: SQL injection with credential/hash access, command
injection, PHP upload execution, reflected and stored XSS, tokenless password change
(CSRF), local file inclusion, brute force without lockout, predictable session
cookies, CSP-page script injection, and CAPTCHA-step password change.

## 9. Missed, deferred or qualified

There are no missed rubric items in either live run. The following qualifications
are recorded in the evidence:

- **Mass assignment endpoint:** vuln-bank's `/update_bio` accepts only the bio;
  the exploitable mass assignment is on `/register` (`is_admin` and `balance`). The
  check ID is the rubric ID `VB-BOPLA-01`; the description records the endpoint
  difference.
- **Stored XSS execution:** the vuln-bank proof stores the raw bio and shows the
  admin user view assigning `user.bio` to `innerHTML`; a browser dialog was not
  driven. DVWA's stored XSS reloads the raw payload in a fresh session.
- **GraphQL admin analytics:** introspection is confirmed with a low-privilege token,
  but the cross-account `transactionSummary(accountNumber: "ADMIN001")` query is
  denied. `VB-GQL-02` records that denial; it is not counted as an additional issue.
- **CSP browser dialog:** the DVWA proof observes the CSP header and the raw injected
  script in the page; it does not claim a browser dialog. The rubric's CSP item is
  covered by the raw sink plus the header.
- **Rate limits:** the vuln-bank AI chat limits unauthenticated and authenticated
  calls per IP. The pilot used an authenticated session and a single injected prompt;
  a later replay can hit HTTP 429 and should be treated as `needs_validation`, not a
  failure of the target.

The DVWA hunt returned two extra candidates outside the rubric: a client-controlled
security-level cookie and upload storage served without a session. They remain
`needs_validation` in `runs/blackbox-dvwa-hunt/` and do not expand the 11-issue
denominator.

## 10. Cleanup and retention

Do not clean up until the evidence and reports are accepted. The pilot keeps both
run directories, including `exploit/`, `hunt/`, `verify.json`, the markdown reports
and the findings/coverage documents.

When cleanup is explicitly approved:

```sh
# Stop the lab containers on the Legion (names are lab-only)
ssh sak-lab 'docker stop dvwa vuln-bank-lab-web-1 vuln-bank-lab-db-1'

# Stop the Mac forwards (one PID per forward)
pkill -f 'ssh .*L 8080:127.0.0.1:8080'
pkill -f 'ssh .*L 15000:127.0.0.1:5000'
```

Keep `runs/blackbox-dvwa-final/` and `runs/blackbox-vuln-bank-final/` after the
containers are stopped. A later run is only comparable when the target repository
revision and profile rubric match.

## 11. Honesty statement

The result is **15/15 covered for the vuln-bank rubric and 11/11 for the DVWA Low
rubric**. It is not a claim that every possible vulnerability was found. The
denominator, the mapping rules and the evidence hashes are in the verification
documents; extras and hunter candidates are listed separately and never expand the
denominator.
