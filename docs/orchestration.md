# Orchestration — three worked examples

This document shows the skill in motion: the same intake, selection, hunting,
verification and reporting loop applied to a web black-box target, a source tree
and a local binary. The web example is a **hypothetical application**, not the
runnable local fixture: its routes, accounts and expected results are
illustrative and were **not observed**. The source and binary examples use local
files and a local process only. None of the examples sends traffic to a live
external target, and none grants authorization.

Shared assumptions:

- `uv` and the `sak` package are installed; `uv run sak --help` works.
- The run IDs are illustrative. A real run ID is timestamped by `sak plan`.
- Commands marked "expected" depend on a module that may not be in a partial
  build. Check `sak --help`; if absent, use the manual fallback in
  [`skills/swiss-army-knife/references/selection.md`](../skills/swiss-army-knife/references/selection.md#manual-fallback).
- Every "Expected" line describes behaviour under the written scope. It is not a
  capture and was not produced by a request from this document.
- No live external target appears in any example.

## Worked example: web black-box

**Situation (hypothetical, not the runnable fixture).** A black-box web app at
`https://app.example.test` with two ordinary users and an admin. You have no
source and no credentials beyond the seeded test accounts. The reserved
`.example.test` name is documentation-only; `sak plan` records it and sends no
traffic.

### 1. Intake

```markdown
# scope.md (excerpt)
Mode: blackbox          Intensity: normal
In scope: https://app.example.test
  Methods: GET, HEAD, POST, PATCH
  PATCH is limited to the caller's own profile and must be restored after the test.
  POST /api/preview may make the app fetch a loopback URL; that internal request
  is part of the authorized test. The tester sends only requests to app.example.test.
  Accounts: A (user), B (user), admin (seed only)
Budget: primary 3, support 4, fallback 3, brute 1; 15 minutes; 1 req/s
Out of scope: DELETE and other destructive writes, DoS, real accounts,
  third-party hosts, cloud metadata
```

The threat model names the object boundary (A → B invoices), the role boundary
(user → admin) and the server-side fetch boundary (URL preview → loopback). Seed
cards: `VIBE-*` for object and role logic, `INV-*` for enforcement consistency,
`SSRF-*` for the preview endpoint.

### 2. Select

```sh
uv run sak doctor
uv run sak catalog validate
uv run sak plan --suite web-blackbox --target https://app.example.test \
  --run-dir runs/demo-web
```

Expected plan shape (roles and caps, not specific card IDs):

```text
wave 1 — primary     Nuclei-class scanner + the two best-ranked hunters
wave 2 — support     content discovery, authz/invariant helpers
wave 3 — fallback    manual replay card
wave 4 — brute       held in reserve unless the owner opens it
excluded             missing requirement, wrong domain, unverified
```

Read `runs/demo-web/plan.json` for the score breakdowns. If `nuclei` is missing,
`sak doctor` prints the install hint; do not install it globally on the target
host. Use the HTTP prompt hunters and manual `curl` replay instead, and record
the fallback.

### 3. Local checks, then approved execution

Run the local checks first. `sak doctor`, `sak catalog show` and the adapter
`--dry-run` read local files, resolve the command and validate the scope
allowlist. They must not contact the target.

```sh
uv run sak run --run runs/demo-web --step nuclei --dry-run
```

Expected: the resolved command, the scope decision, the requirements and the
rate/time budget, with no network request. A refusal for a missing binary or an
out-of-scope host is a valid result. Any readiness or normal-operation request is
**active execution**, not part of the dry run: it comes after the scope gate, an
explicit `--execute` approval recorded in `state.json`, and a budget check. Then
run the approved scanner step:

```sh
uv run sak run --run runs/demo-web --step nuclei --execute
```

Expected (illustrative, not observed): JSONL output parsed into candidate records
under `logs/` and `evidence/`, with `-no-interactsh` and the scope rate limit. A
scanner hit is a candidate, not a finding.

### 4. Mutate and hunt

The first wave asks three questions, one per hunter. All three use a method the
scope lists and a test account; H-02 writes only A's own profile and is restored
immediately after the test.

| Hunter | Hypothesis | Principal | Cheapest test | Expected evidence (illustrative) |
|---|---|---|---|---|
| H-01 | Invoice IDs are not ownership-checked | A | `GET /api/invoices/842` as A (B owns 842) | 200 with B's fields |
| H-02 | `role` is mass-assignable on profile update | A | `PATCH /api/profile` with `{"role":"admin"}` | 200; `GET /api/me` shows `admin`; restore to `user` |
| H-03 | URL preview fetches loopback | A | `POST /api/preview` with `{"url":"http://127.0.0.1:9/admin"}` | 200 with an internal body; anything weaker is a weak signal |

Hunters run read-only and in parallel with separate sessions; H-02 mutates, so it
runs alone, after approval, with a restore step (write `role: user` back and
re-seed A if the profile is not clean). Each hunter gets one evidence contract
from
[`prompt-mutation.md`](../skills/swiss-army-knife/references/prompt-mutation.md#evidence-contract).

### 5. Classify, verify, report

Expected labels below are illustrative; no request was sent for this document.

- H-01 returns B's invoice data and the negative control (A's own invoice)
  behaves → `signal`.
- H-02 accepts the role and `GET /api/me` reports `admin` → `signal`; restore the
  profile immediately and record the restore. If the app rejects the field, the
  result is `noise`; do not retry a different field name unless the model says it
  is accepted elsewhere.
- H-03 returns an internal body → `signal`; redact any token. A distinctive
  connection result without a body is at most `weak_signal`, with a sharper test;
  if no cheaper test remains, `needs_validation`.

Send all three to `VER-01` in a fresh session. The verifier re-creates A's
session, repeats the request from the contract, re-applies H-02 and restores it
again, tries the alternative explanation ("B shared the invoice"), and records
the attempt. Then:

```sh
uv run sak report runs/demo-web      # expected (T6)
```

Produces `REPORT.md`, `FINDINGS-DETAIL.md` and `NEEDS-VALIDATION.md`. The
coverage section lists each hypothesis as verified, weak or blocked — including
the restored write — rather than as "no findings".

**Stop condition:** all ledger rows resolved, 15 minutes spent, or two waves with
no signal. The brute reserve stays closed.

## Worked example: source audit

**Situation.** A repository at a pinned revision. No running app. The question is
whether user-controlled input reaches a dangerous sink, and whether a permission
check is missing.

### 1. Intake

```markdown
# scope.md (excerpt)
Mode: source            Intensity: normal
In scope: local clone at <sha>; read-only analysis
Out of scope: running the app, live hosts, dependency SaaS, secret use
Budget: primary 2, support 3, fallback 2, brute 0; 20 minutes
Evidence: file:line, code excerpt, reachable path, no secrets
```

Threat model: HTTP handlers → service layer → data store; the tenant identifier
comes from the session, not the body; file uploads are parsed by a library. Seed
cards: `INV-*` enforcement and assumption cards.

### 2. Select

```sh
uv run sak plan --suite web-source --target . --run-dir runs/demo-source
```

Expected roles: the vendored `security-audit` skill as primary, Semgrep and
Gitleaks as support (manual cards in v1), invariant prompts as fallback. If the
source suite profile differs in your build, use the suite the catalog provides;
do not edit a suite to force a card in.

### 3. Execute

Delegate the audit to the vendored skill at
`vendor/skills/security-audit/SKILL.md` (MIT). Give it the pinned revision, the
threat model and the evidence contract. Then run the deterministic cards by hand
and record the exact command:

```sh
# Pin the ruleset locally so the audit does not fetch a remote registry.
semgrep --config rules/ --json --output runs/demo-source/logs/semgrep.json .
gitleaks detect --source . --report-format json \
  --report-path runs/demo-source/logs/gitleaks.json
```

A Semgrep rule match is a lead. The hunter must show the path: route → handler →
service → sink, with the authorization check that is missing or misplaced.

### 4. Mutate and hunt

Source mutations are cheaper than black-box ones:

| Operator | Question | Example |
|---|---|---|
| Principal swap | Does the query filter on the session tenant? | `WHERE id = ?` without `tenant_id` |
| Trusted input | Does the body override the session user? | `user_id` in the payload |
| Composition | Can two handlers combine into a bypass? | invite + accept |
| Failure path | Does a rejected request still write? | transaction commits before the check |
| Parser split | Do two parsers disagree? | path normalization before/after routing |

Parallel hunters can read different modules. They do not run the app; the
evidence contract is file:line plus a code path, and the verifier checks the path
independently.

### 5. Verify and report

Verification for a source finding is a second reading and a reachability check:
the verifier starts from the route, not the sink, and confirms the check is
absent on every path. If the app can be run locally, a single authorized request
can strengthen a `confirmed` verdict; it is not required.

Report one finding per root cause: "invoice handler omits tenant filter" covers
every route that calls it. List the routes as locations. Mark unreachable code
as `rejected` with the reason, not `needs_validation`.

**Stop condition:** the modelled paths are read, the budget is spent, or the
remaining code needs a running environment that is out of scope.

## Worked example: binary triage

**Situation.** A local ELF binary and its loader, supplied for an authorized
assessment. No remote service. The question is which mitigations are present and
whether an obvious memory-safety bug is reachable with a local harness.

Binary work is cataloged and vendored in v1, not deeply executed: stay at triage
and a local proof of concept, and stop before anything that risks the host.

### 1. Intake

```markdown
# scope.md (excerpt)
Mode: binary            Intensity: normal
In scope: ./target (sha256 …), local execution only, no network
Out of scope: remote services, kernel exploitation, persistence, host changes
Budget: primary 2, support 2, fallback 1, brute 0; 20 minutes
Evidence: checksec output, crash input, backtrace, harness command
```

Threat model: input parser → stack/heap → control flow; trust boundary is the
process boundary; the asset is the host and the binary's secrets.

### 2. Select

```sh
uv run sak plan --suite binary --target ./target --run-dir runs/demo-bin
uv run sak doctor
```

Expected primary: the vendored `pwn-hunter` skill (MIT). Support: `checksec` and
`pwntools` under a local harness. If `checksec` or `pwntools` is missing, use the
documented install hint in a local virtual environment, or stay with static
triage. Do not install globally.

### 3. Execute

```sh
checksec --file=./target
python3 - <<'PY'
from pwn import ELF
elf = ELF("./target", checksec=False)
print(elf.checksec())
PY
```

Then follow `vendor/skills/pwn-hunter/SKILL.md` with the local binary, a fixed
seed and a bounded input generator. Capture the exact command, the input hash and
the observed crash or control-flow effect under `evidence/`.

### 4. Mutate and hunt

| Operator | Question | Example |
|---|---|---|
| Length | Where is the boundary? | 64, 128, 256 bytes |
| Encoding | Does the parser normalize? | UTF-8, NUL, oversized length |
| State | Does a prior command change the check? | menu option order |
| Mitigation | Which protection changes the strategy? | PIE, canary, NX, RELRO |
| Reuse | Is there a second path to the same sink? | alternate command parser |

Hunters are local processes, one input family each, capped and time-boxed. A
crash is a candidate; it is not a confirmed exploit until the verifier reproduces
it from the minimal input and shows the effect.

### 5. Verify and report

The verifier re-runs the minimal input from a clean process, checks the offset
and the mitigation state, and records the exact environment (binary hash, libc,
ASLR setting). A crash without control-flow impact is `needs_validation` or
`rejected` depending on the claim. Stop before building a weaponized chain that
leaves the local harness.

**Stop condition:** mitigations and the reachable bug are characterized, the
budget is spent, or the next step would need a remote target or host changes.

## Shared checklist

Run this before declaring any example complete.

- [ ] `scope.md` names the asset, method, account, window and forbidden actions.
- [ ] `threat-model.md` names assets, entrypoints, boundaries, principals and
      invariants.
- [ ] The plan (CLI or manual) is recorded with scores and exclusions.
- [ ] Every active step had a dry run and a recorded approval.
- [ ] Hunters had one evidence contract each; parallel hunters were read-only.
- [ ] Every signal has a class and a next action; every ledger row is resolved.
- [ ] A fresh verifier tried to disprove each candidate and recorded the attempt.
- [ ] Findings are deduped by root cause and carry one of the three verdicts.
- [ ] `REPORT.md`, `FINDINGS-DETAIL.md` and `NEEDS-VALIDATION.md` exist and link
      redacted evidence with hashes.
- [ ] The learn step records the measured result and any ranking or prompt
      change.
- [ ] The human owner has the report; nothing was sent or published by the
      agent.
