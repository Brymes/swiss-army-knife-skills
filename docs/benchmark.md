# Skill benchmark — dummy targets

This benchmark measures the installed `swiss-army-knife` skill and the `sak`
engine against two fixed, authorized loopback labs: DVWA at Low security and the
pinned vuln-bank lab. It is a **rubric-coverage benchmark**, not a claim that every
possible vulnerability was found.

The durable records are:

- `benchmarks/vuln-bank.json`
- `benchmarks/dvwa-low.json`
- `benchmarks/README.md`

The guide uses the fixed rubric denominator, not a raw finding count. Each record
carries the target, profile, rubric counts, confirmed issue ids, severity, entrypoint,
check id, evidence artifact and SHA-256, request count, hunt summary and caveats.
Secrets are not stored; the source run evidence is under the gitignored `runs/`
directories.

## 1. Why these targets

DVWA and vuln-bank are deliberately vulnerable, public, MIT-licensed labs with a
stable profile in this repository. They cover the two sides of the skill:

- **DVWA Low** exercises classic web checks: SQL injection, command injection,
  upload/RCE, reflected and stored XSS, CSRF, LFI, brute force, weak session ids,
  CSP and CAPTCHA.
- **vuln-bank** exercises API and business logic: JWT/auth, IDOR/BOLA, mass
  assignment, SQL injection in a JSON API, negative transfer, client-controlled card
  funding, merchant replay, GraphQL introspection, SSRF, upload, information
  disclosure and prompt injection.

Both are loopback-only. No internet-facing host is contacted.

## 2. Method

For each target:

1. Start the lab container and set DVWA to Low.
2. Create the run `scope.md` with the loopback host, methods and budget.
3. Run the profile's explicit `exploit.checks` with `sak exploit`.
4. Score the profile's `expected` rubric with `sak verify`.
5. Render the confirmed findings, coverage ledger and reports with `sak report`.
6. Record the confirmed issue ids, evidence hashes, requests and caveats in the
   benchmark JSON.

A benchmark run passes only when:

- `sak verify` reports every expected issue as `covered`;
- there are no `unknown_ids`, `extras` or `ambiguous` records;
- every confirmed finding has a readable evidence artifact whose SHA-256 matches;
- `sak report` renders the same confirmed count with zero coverage gaps.

Hunt candidates are logged but never counted as confirmed findings.

## 3. Baseline results

Live run on 2026-11-22 against a remote lab host through a macOS SSH tunnel.

| Target | Rubric | Confirmed | Coverage | Check artifacts | Requests | Extra hunt candidates |
|---|---|---|---|---|---|---|
| vuln-bank | 15 | 15 | 15/15, ratio 1.0 | 16 (15 rubric + GraphQL denial) | 457 | 1 candidate, 1 timeout |
| DVWA Low | 11 | 11 | 11/11, ratio 1.0 | 11 | 169 | 2 candidates |

Both verification documents report `confirmed=15/needs_validation=0/rejected=0`
and `confirmed=11/needs_validation=0/rejected=0`, with zero missed, partial or
deferred rubric items.

## 4. What the benchmark covers

### vuln-bank

| Issue | Class | Proof |
|---|---|---|
| `VB-AUTH-01` | authentication | Login SQL injection returns an admin token |
| `VB-AUTH-02` | authentication | JWT re-signed with the exposed secret reaches the admin panel |
| `VB-BOLA-01` | idor | Tester B reads Tester A's transaction history |
| `VB-BOLA-02` | idor | Tester B reads a card object created by Tester A |
| `VB-BOPLA-01` | authorization | Registration accepts `is_admin` and `balance` |
| `VB-SQLI-01` | sql-injection | Bill-payment `biller_id` produces a database syntax error |
| `VB-XSS-01` | xss-stored | Bio is stored raw and the admin user view assigns it to `innerHTML` |
| `VB-NEG-01` | business-logic | A negative transfer increases the sender balance |
| `VB-CARD-01` | business-logic | Client `exchange_rate` over-credits a card |
| `VB-MERCH-01` | business-logic | Two charges with one order id complete; a negative charge is accepted |
| `VB-GQL-01` | admin-privilege | Introspection succeeds with a low-privilege token |
| `VB-SSRF-01` | ssrf | The server fetches the loopback internal secret and serves a copy |
| `VB-UPLOAD-01` | unrestricted-upload | A text file is accepted and served as a non-image |
| `VB-INFO-01` | information-disclosure | `.env`, `.env.bak` and `/debug/users` are exposed |
| `VB-AI-01` | prompt-injection | The injected support prompt makes the assistant access the database |

### DVWA Low

| Issue | Class | Proof |
|---|---|---|
| `DVWA-SQLI-01` | sql-injection | UNION payload returns the admin row and password hash |
| `DVWA-CMDI-01` | command-injection | `; id` appends uid/gid output |
| `DVWA-UPLOAD-01` | unrestricted-upload | PHP marker upload is served and executed |
| `DVWA-XSS-R-01` | xss-reflected | Payload reflected unencoded |
| `DVWA-XSS-S-01` | xss-stored | Payload stored and rendered raw on reload |
| `DVWA-CSRF-01` | csrf | Tokenless GET changes the password; a fresh login proves it |
| `DVWA-FI-01` | file-inclusion | `page=/etc/passwd` returns `root:x:0:0` |
| `DVWA-BRUTE-01` | brute-force | Wrong password rejected; demo password accepted without lockout |
| `DVWA-SESSION-01` | session-management | `dvwaSession` increments predictably |
| `DVWA-CSP-01` | csp-bypass | CSP header present and injected script reflected raw |
| `DVWA-CAPTCHA-01` | captcha-bypass | Step-2 POST changes the password; a fresh login proves it |

## 5. Reproduce

The full operator sequence is in [blackbox-pilot.md](blackbox-pilot.md). The short
form for a running lab is:

```sh
uv run sak exploit --run runs/blackbox-vuln-bank-final \
  --target http://127.0.0.1:15000 \
  --profile targets/vuln-bank/blackbox/profile.yaml --json
uv run sak verify --run runs/blackbox-vuln-bank-final \
  --profile targets/vuln-bank/blackbox/profile.yaml --json
uv run sak report runs/blackbox-vuln-bank-final

uv run sak exploit --run runs/blackbox-dvwa-final \
  --target http://127.0.0.1:8080 \
  --profile targets/dvwa/blackbox/profile.yaml --json
uv run sak verify --run runs/blackbox-dvwa-final \
  --profile targets/dvwa/blackbox/profile.yaml --json
uv run sak report runs/blackbox-dvwa-final
```

On Kali, replace the vuln-bank target with `http://127.0.0.1:5000`. On the Mac,
use the `15000` tunnel; port `5000` is commonly AirTunes.

## 6. How to interpret a score

- **Coverage** is the headline. `15/15` or `11/11` means every expected issue in
  that profile was proven; it does not mean the application has no other bugs.
- **Confirmed findings** must equal the confirmed rubric count. A `sak report` with
  fewer confirmed findings than `sak verify` is an evidence-integrity failure.
- **Unknown ids, extras and ambiguous records** must be zero for a clean benchmark.
  A new check id outside the rubric should be added to the rubric deliberately, not
  silently counted.
- **Requests** are a cost signal, not a score. A change that adds many requests
  without new coverage is a regression in efficiency.
- **Hunt candidates** are exploratory. A candidate is not a finding until a profile
  check or a verified finding proves it.

## 7. Caveats

- vuln-bank mass assignment is exploitable on `/register`, not the rubric-named
  `/update_bio`; the check id remains the rubric id and the artifact records the
  endpoint difference.
- vuln-bank stored XSS proves raw storage and the admin `innerHTML` sink; a browser
  dialog was not driven. DVWA stored XSS reloads the raw payload in a fresh session.
- GraphQL introspection is confirmed; the cross-account admin summary is denied and
  recorded as a denial check (`VB-GQL-02`), not as another issue.
- DVWA CAPTCHA changes the password but does not print the success text; a fresh
  login proves the change and the original demo password is restored.
- The vuln-bank hunt's one candidate targeted the local fixture at `127.0.0.1:8765`,
  not vuln-bank; VIBE-02 timed out. Neither affects the rubric result.
- The DVWA hunt candidates (client-controlled security cookie; uploads served
  without a session) are outside the 11-issue rubric and remain `needs_validation`.
- The benchmark runs on loopback lab targets with documented demo accounts. It is
  not a production benchmark and says nothing about WAFs, scale or real data.

## 8. Adding a benchmark target

1. Add a `sak.blackbox.profile.v1` profile with a stable `expected` rubric.
2. Add explicit `exploit.checks` when the generic derivation cannot prove a class.
3. Run `sak exploit`, `sak verify` and `sak report` live on the lab.
4. Copy the confirmed records into `benchmarks/<target>.json` with the same shape.
5. Record the caveats, hunt result and exact commands.
6. Add the target to this document and to the docs test.

Do not paste tokens, cookies, passwords, keys, card numbers or environment values
into a benchmark record. The evidence artifacts already mask them.
