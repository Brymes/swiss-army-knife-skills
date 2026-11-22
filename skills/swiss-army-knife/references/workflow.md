# Intake and scope

The first hour decides whether the engagement is legitimate. Everything later
depends on a written scope, a named target, an owner and a budget. Do not run a
tool before this file's gate passes.

## Intake gate

Ask these in order. A "no" or "unknown" stops the run.

| # | Question | Pass condition |
|---|---|---|
| 1 | Who owns the target, and who authorized this? | Named owner, named authorizer, written permission or a published program policy |
| 2 | What exactly is in scope? | Hosts, ports, paths, API versions, repositories, binaries, accounts |
| 3 | What is out of scope? | Explicit exclusions, including third-party services, shared infrastructure and real users |
| 4 | Which mode and intensity? | `blackbox`, `greybox`, `whitebox`, `source`, `binary` or `passive`; `passive`, `normal` or `brute` |
| 5 | Which accounts may be used? | Test accounts or fixtures; never production user accounts or real credentials |
| 6 | What are the time, rate, request and cost budgets? | Numbers, not "reasonable" |
| 7 | What is forbidden? | Destructive actions, DoS, persistence, data exfiltration, social engineering, third-party pivoting |
| 8 | What is the disclosure route and window? | Human owner, private channel, embargo; the agent never sends |
| 9 | Where do evidence and reports live? | A run directory with access limited to the engagement |
| 10 | Who is reachable if something breaks? | Named contact and stop procedure |

Record the answers in `runs/<run-id>/scope.md`. If the request is a bug-bounty
program, paste the program's scope rules rather than paraphrasing them, and
prefer the narrower reading when two readings disagree.

## Scope template

Copy this into `runs/<run-id>/scope.md` and fill every line. `TBD` is not a
value; it is a blocker.

```markdown
# Scope — <engagement> — <run-id>

- Owner / authorizer: <name, role, date>
- Authorization source: <signed permission, program policy URL, ticket ID>
- Engagement window: <start> to <end>, <timezone>
- Mode: <blackbox|greybox|whitebox|source|binary|passive>
- Intensity: <passive|normal|brute>
- Run directory: runs/<run-id>/

## In scope

| Asset | Type | Allowed methods / actions | Notes |
|---|---|---|---|
| https://app.example.test | web | GET, HEAD, POST (test accounts only) | staging copy |
| /api/v1 | api | GET, POST | documented endpoints |
| github.com/org/repo@<sha> | source | read-only clone | reviewed revision |
| 127.0.0.1:8765 | fixture | all fixture routes | local lab only |

## Out of scope

- <third-party hosts, payment providers, shared auth, production data>
- Destructive actions, DoS/load tests, persistence, data exfiltration.
- Real user accounts or real personal data. Use accounts: <A>, <B>, <admin>.

## Accounts and credentials

| Label | Role | How provisioned | Secret location |
|---|---|---|---|
| A | normal user | fixture seed | environment variable, never in a file |
| B | second tenant | fixture seed | environment variable |
| admin | administrator | fixture seed | environment variable |

## Budget

- Portfolio caps: primary <3>, support <4>, fallback <3>, brute <1>.
- Wall clock: <minutes> total, <minutes> per wave.
- Requests: <n> total, <n>/s per host.
- Cost: <USD> for models or paid APIs.
- Evidence: store redacted captures only, <max MB>.

## Forbidden actions

- <destructive writes, deletes, account takeover, password spraying, phishing>
- Any request that changes another user's data, even to "prove" impact.
- Scanning hosts not listed above, including DNS neighbours and cloud metadata.

## Disclosure and stop

- Human owner: <name, channel>
- Disclosure window: <days>
- Stop contact: <name, channel>
- If impact exceeds the plan: stop, preserve logs, notify the owner.
```

## Target and mode

Choose the mode from what you can see, not from what you hope to prove.

| Mode | You have | Start with | Do not |
|---|---|---|---|
| `blackbox` | URL or app, no source | Nuclei, HTTP prompt hunters (`INV-*`, `VIBE-*`, `SSRF-*`) | Assume hidden endpoints exist |
| `greybox` | one low-privilege account | Authz and object-boundary cards, then scanners | Escalate to another role without approval |
| `whitebox` | source and configuration | `security-audit` skill, Semgrep/Gitleaks/Trivy cards | Report a code pattern without a reachable path |
| `source` | repository only | `security-audit`, invariant cards, targeted grep | Run the app or touch a live host |
| `binary` | local binary and loader | `pwn-hunter`, `checksec`, local harness | Exploit a remote service or risk the host |
| `passive` | public data only | Webseek, public records | Send traffic to the target |

Write the mode and the intensity into `scope.md`; the planner filters on them.
`brute` intensity is a reserve, never a starting point.

## Threat-model template

A threat model turns "test everything" into a bounded list. One page is enough
for a small target; keep it current as signals arrive. Copy this into
`runs/<run-id>/threat-model.md`.

```markdown
# Threat model — <target> — <run-id>

## Assets
- <what an attacker wants: other tenants' invoices, admin actions, tokens, files>

## Entrypoints
| Entrypoint | Method | Auth | Inputs | Notes |
|---|---|---|---|---|
| /api/invoices/{id} | GET | user session | path id | sequential IDs |
| /upload | POST | user session | file, filename | parsed server-side |

## Trust boundaries
- anonymous → user session
- user A → user B tenant
- user → admin
- app server → internal metadata / file system
- model context → tool calls (LLM targets)

## Principals
| Principal | Can | Cannot | Test account |
|---|---|---|---|
| anonymous | read public pages | mutate state | none |
| user | own objects | other tenants | A |
| admin | all objects | — | admin |

## Invariants to attack
- Object access requires ownership or an explicit grant.
- Role changes require admin authority and are audited.
- Server-side fetches cannot reach internal addresses or metadata.
- One tenant's response never contains another tenant's data.
- A failed request has no side effect.

## Assumptions and unknowns
- <session lifetime, cache layer, CDN, feature flags, background jobs>

## Top hypotheses
| ID | Hypothesis | Boundary | Cheapest test | Expected evidence |
|---|---|---|---|---|
| H-01 | Invoice IDs are not ownership-checked | A → B | GET B's invoice as A | 200 with B's fields |
| H-02 | Role field is mass-assignable | user → admin | PATCH own profile with role | role changes |

## Out of scope for modelling
- <vendored components, upstream providers, physical access>
```

## Dry-run first

A dry run is a local inspection, not a lighter version of the attack. Checks and
dry runs inspect local configuration and tools only: they resolve the binary,
render the command, validate the scope allowlist and budget, and report missing
requirements. They must not contact the target or any third party.

1. **Local checks.** `sak doctor` and `command -v` for the card's requirements;
   does `scope.md` exist and name the host; are `plan.json`, `state.json` and the
   budget present?
2. **Local dry run.** Adapter `check` or `--dry-run` renders the exact command,
   confirms the host is in the scope allowlist, confirms requirements and budget,
   and exits without a network request. A dry run that contacts the target is an
   adapter bug, not authorization.
3. **Readiness request (active).** If normal operation must be observed, that
   request is active execution. It comes after the scope gate, an explicit
   `--execute` approval recorded in the run log, and a budget/rate check. Keep it
   to one low-rate request and record it.
4. **Execute the step.** Run the approved step with `--execute`, the recorded
   approval and the remaining budget.

If a check or dry run reports a missing binary, a missing key, a missing scope
entry or an out-of-scope host, stop and use the fallback card. Do not install
global tools silently and do not widen the scope to make a tool work.

## Budget

Budget has two layers; record both.

- **Portfolio budget** — role caps from the suite: `primary`, `support`,
  `fallback`, `brute` (defaults `3/4/3/1`). A cap is a ceiling, not a target.
- **Execution budget** — wall clock, request count, per-host rate, retries, model
  cost and evidence size. Put the numbers in `scope.md` and decrement them in
  `state.json`.

A wave that spends the budget without a signal is a result: record it and move
to the fallback rather than retrying the same thing louder.

## Coverage ledger

The ledger is the honest answer to "what did you actually test?". Keep one row
per asset × entrypoint × boundary × hypothesis. Update it after every wave,
including skipped and blocked rows.

| Column | Meaning |
|---|---|
| `id` | Stable row ID, e.g. `COV-012` |
| `asset` | Host, path or file |
| `entrypoint` | Route, function, binary command |
| `boundary` | Trust boundary being crossed |
| `hypothesis` | What you expected to be violated |
| `method` | Tool, prompt card or manual test |
| `status` | Coverage state, e.g. `covered`, `partial`, `skipped`, `blocked` |
| `evidence` | Evidence path or `none` |
| `notes` | Why skipped or blocked; next action |

Rules:

- A row may be `covered` only when evidence exists or a negative control proves
  the expected rejection.
- `skipped` needs a reason (out of scope, not applicable, budget); `blocked`
  needs an owner or a missing prerequisite.
- New signals add rows; they never delete inconvenient ones.
- The report's coverage section reads this ledger, not memory.

The machine-readable ledger and its schema are owned by the findings module
(`sak findings`); this table is the human view. Keep the same IDs in both.

## Run directory

All artifacts for one engagement live in one directory. Do not scatter evidence
across the repo or a chat thread.

```text
runs/<run-id>/
  scope.md               # this file's scope template, filled
  threat-model.md        # this file's threat-model template, filled
  plan.json              # `sak plan --run-dir runs/<run-id>`
  state.json             # current wave, budget remaining, next action
  coverage-ledger.json   # machine-readable ledger
  findings.json          # all verdicts, including rejected
  evidence/              # redacted captures, one subdir per finding
  logs/                  # tool output and command lines
  REPORT.md              # summary for the human owner
  FINDINGS-DETAIL.md     # per-finding reproduction and remediation
  NEEDS-VALIDATION.md    # open questions, blockers, next actions
```

A later session should be able to resume from this directory alone: read
`state.json`, then the ledger, then the open rows in `NEEDS-VALIDATION.md`.

Next: choose the portfolio in [selection.md](selection.md).
