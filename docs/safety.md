# Safety

`sak` is for **authorized** security assessment. The tool cannot grant
authorization and does not try. If the scope is missing or ambiguous, stop and
ask; do not infer permission from a URL, a ticket title or a "test this" request.

This page is the repository-level contract. The operating detail for agents is in
[`skills/swiss-army-knife/references/safety.md`](../skills/swiss-army-knife/references/safety.md).

## Authorization

Before any active step:

1. The requester owns the target or has written permission that names it.
2. `runs/<run-id>/scope.md` exists and names the allowed hosts, paths, methods,
   accounts, data and time window.
3. The scope is specific enough to reject a stray host: a wildcard is not a scope.
4. The target is inside that scope. `sak run --execute` refuses otherwise.
5. The engagement owner knows the budget and the stop rules.

Scope template:

```markdown
# Scope — <engagement>

- Authorization: <who authorized this, and where the permission is recorded>
- In scope: https://app.example.test
  - Methods: GET, HEAD, OPTIONS, POST (documented writes only)
  - Paths: /api/*, /login, /profile
  - Accounts: two seeded test users and one admin, never a real customer
- Out of scope: other hosts, subdomains, third-party APIs, cloud metadata,
  destructive writes, denial of service, real personal data, social engineering
- Window: 2026-11-15 10:00–12:00 UTC
- Rate: 1 request/second; stop on 5xx or a state change outside the plan
- Budget: primary 3, support 4, fallback 3, brute 0
- Approval: <name> for any brute card or state-changing replay
```

The local fixture is the one built-in exception: it is an authorized loopback
test target owned by this repository. Its host is `127.0.0.1`, its database is a
deterministic fake seed, and its server refuses a non-loopback bind. The fixture
is for tests and the demo only; do not point the harness at a live system and
call it a fixture.

## Forbidden actions

Never, by default:

- test a host that is not named in `scope.md`;
- run a destructive payload, delete data, or change state outside the documented
  test path;
- run denial-of-service, resource-exhaustion, credential-stuffing, password
  spraying or unbounded fuzzing;
- touch real user accounts, real personal data or production secrets;
- use a brute card without explicit owner approval (the planner keeps it in
  reserve for this reason);
- execute an external engine, install a global tool, or start a container as a
  side effect of planning;
- publish, send, disclose or notify anyone. The agent drafts; a human sends.

If an action would cross one of these lines, stop, write the blocker and next
action, and hand back. A refusal is a valid result.

## Dry run first

Adapters support `--dry-run` and default to it. `sak run` prints the resolved
command and makes no request. `sak engine install/up/down/status` is also a dry
run unless `--execute` is passed.

Active execution requires all of:

1. a valid `scope.md`;
2. `--execute` on the step;
3. a recorded reason and an approved budget;
4. a target inside the scope allowlist.

`sak doctor`, `sak catalog`, `sak plan`, `sak prompts` and `sak report` read local
files only. They are safe to run before any approval.

## Secrets and data

Never print, log, commit or store:

- passwords, API keys, session IDs, cookies, authorization headers or reset
  tokens;
- private keys or cloud credentials;
- real personal data, customer records or production payloads;
- raw provider or model request bodies that contain any of the above.

The code masks common secret shapes in commands, evidence summaries, reports and
JSON output: auth headers, bearer tokens, `key=value` and space-separated CLI
credentials (`--api-key <value>`), AWS access key IDs, GitHub tokens, Slack
tokens and PEM private keys. The optional agent command is split without a shell,
so a run-directory path containing spaces, quotes or `;` stays one argument, and
its command text, stderr, timeout/error observations and persisted records pass
through the same masking. Masking is a safety net, not a license to paste a
secret. Do not write a secret into a card, test, log or report in the first
place.

Evidence is stored raw and immutable because a verifier must be able to check it.
That means the evidence must be **collected** without secrets: redact at capture
time, keep only the fields needed for the proof, and use fixture or synthetic
data. `sak report` masks on render, but the file on disk is the artifact that
matters.

Fixture accounts, fixture reset tokens and `*.example.test` addresses are fake
seeded data. They are still handled as if they were real: the demo and eval
record only the observation ("another user's email was returned"), never the
value.

## Rate and blast radius

- Read-only requests may run in parallel, with a per-host rate limit (default
  one request per second unless the scope says otherwise).
- Writes, deletes, spends, password changes, messages and any state change are
  serialized, rate-limited and explicitly approved.
- Prefer the smallest request that proves the invariant. Keep a benign control.
- Stop on an unexpected 5xx, a state change outside the plan, or a signal that
  the target is shared with real users.
- Clean up only what the scope authorizes. Restore fixture state with the
  fixture's own `--reset`, not with ad-hoc deletes.
- The deterministic eval and demo stay on loopback and record cost `$0.00`. An
  optional external agent may use network or a paid model: treat that as separate
  authorization, keep the raw credential out of artifacts, and never record its
  cost as measured zero.

## Evidence and claims

- `confirmed` requires reproducible evidence: a redacted request/response plus
  controls for web/API; a pinned file, line and reachable path for source; a
  minimal input, environment and observed effect for binary.
- A hunter may produce a candidate, never a `confirmed` finding. A fresh
  verifier tries to disprove it.
- A `confirmed` record whose evidence is missing or whose hash no longer matches
  is excluded from confirmed counts and verified coverage.
- Do not upgrade a claim because a report looks thin. Leave it
  `needs_validation` with an open question and next action.
- A negative control that fails is a harness or target regression: investigate
  it before trusting any positive result.

## Licensing safety

- This repository and the `swiss-army-knife` skill are MIT.
- MIT vendored skills may be linked by `install.sh`; GPL, AGPL and unlicensed
  code may not be vendored or copied.
- Heavy or unclear-license engines (T3MP3ST, PentAGI, ARTEX, Blackbird,
  AppleResearch) stay external under the gitignored `vendor/external/` path and
  are operated only through explicit engine cards.
- Upstream pins, licenses and per-file hashes live in
  [`vendor/sources.lock.json`](../vendor/sources.lock.json) and
  [`vendor/PROVENANCE.md`](../vendor/PROVENANCE.md). Notices are in
  [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).
- If a license is unclear, stop and ask before copying a single file.

## Stop rules

Stop the run, record the blocker and the next action, and hand back when:

- the target, host, path, account or window is outside `scope.md`;
- an action would be destructive, denial-of-service or touch real user data;
- a step needs `--execute` or a brute card without recorded approval;
- the time, request, rate or cost budget is exhausted;
- two consecutive waves add no new signal and the ledger has no open rows;
- a tool, credential or engine is missing and the fallback cannot cover it;
- the verifier cannot reproduce a claim and no cheaper test remains;
- evidence would require storing a secret or personal data that cannot be
  redacted.

## Reporting and disclosure

`REPORT.md`, `FINDINGS-DETAIL.md` and `NEEDS-VALIDATION.md` are drafts for a human
owner. They state coverage gaps and unverified claims explicitly. They never
include a live secret. `sak` has no send, publish or notify action; distribution
and disclosure are human decisions.
