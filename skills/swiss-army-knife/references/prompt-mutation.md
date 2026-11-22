# Prompt mutation and parallel hunting

A scanner asks questions its templates already know. A prompt hunter asks a
question derived from *this* target's threat model. The loop below keeps that
flexibility bounded: hypotheses are small, evidence is specified up front, and
parallelism is read-only.

```text
scope + threat model
        │
        ▼
   seed prompt  ──►  mutate (MUT-01)  ──►  bounded hypotheses
        ▲                                        │
        │                                        ▼
  new signal  ◄──  classify  ◄──  parallel read-only hunters
        │                                        │
        └────────── next wave ◄──────────────────┘
                                                 │
                                                 ▼
                                     verifier → report
```

## Seed

Pick the smallest set of prompt cards that covers the modelled boundaries. One
seed per boundary is enough for the first wave.

| Boundary in the threat model | Seed cards |
|---|---|
| Object ownership, roles, tenant isolation | `VIBE-01`…`VIBE-14`, `INV-*` authorization invariants |
| Request handling and state transitions | `INV-*` composition, ordering, rollback and rebinding cards |
| Server-side fetches | `SSRF-01`…`SSRF-08` |
| LLM context, retrieval and tools | `LLM-01`…`LLM-08` |
| Unclear or conflicting evidence | `MUT-01`, then `VER-01` |

Write the seed choice into the run log with the card IDs and why each was
chosen. If a seed card's `applies_to` does not match the target, skip it and
record the skip; do not bend the target description to fit the card.

## Mutate

`MUT-01` (threat-model-aware mutation) turns the threat model into bounded
hypotheses. If the prompt module is unavailable, do the same steps by hand. Each
hypothesis must fit on one screen and contain all seven fields:

```markdown
### H-007 — Invoice read across tenants

- Asset / entrypoint: GET /api/invoices/42 on app.example.test
- Boundary: user A → user B tenant
- Invariant: object access requires ownership or an explicit grant
- Suspected violation: the handler checks authentication but not ownership
- Cheapest test: one GET as A for an invoice ID owned by B
- Expected evidence: 200 with B's invoice fields, A's session cookie, no B login
- Stop condition: 403/404, three attempts, or any state change → stop and record
```

Mutation operators, applied one at a time:

| Operator | Question it asks | Example |
|---|---|---|
| Principal swap | What changes if a different role makes the same request? | A reads B's object |
| Path/identity rebinding | Can two identifiers disagree? | session user vs body `user_id` |
| Composition | Does step 1 make step 2 legal when it should not? | invite → accept → read |
| Ordering | Does the check happen before the side effect? | delete then re-add |
| Failure path | What happens on a rejected request? | 4xx that still writes |
| State reversal | Does undo revoke the grant? | remove member, token still valid |
| Encoding/parse split | Do two parsers disagree? | `%2f`, unicode, duplicate keys |
| Boundary crossing | Can a server-side fetch reach inside? | URL fetch to metadata |
| Volume/quota | Does the limit apply per account or per request? | race two credits |

Bound the wave: default **five hypotheses**, each with one cheapest test. More
hypotheses than budget is a sign the threat model is too vague, not a reason to
run longer. Never re-run an unchanged hypothesis; change the operator, the
principal or the path, or mark it rejected.

## Hunt in parallel

One hunter = one hypothesis (or one narrow class) + one evidence contract. The
hunter brief is self-contained: it gets the target, its account, its hypothesis,
its expected evidence and its stop condition. It does not get the other hunters'
transcripts.

Parallel rules:

- **Read-only only.** GET, HEAD, OPTIONS, or a replay of a step already approved
  and performed in a sandbox account. Writes, deletes, purchases and sends are
  serialized and approved.
- **Separate principals.** One account per hunter; no shared cookies, tokens or
  browser profile. A cross-tenant test needs A and B to be genuinely separate.
- **Separate directories.** `runs/<run-id>/evidence/<hunter-id>/` and
  `logs/<hunter-id>.log`. No hunter writes another's files.
- **Cap concurrency** (three by default) and divide the rate budget across
  hunters. Three hunters at one request per second is three requests per second
  to the target.
- **No cross-talk.** A hunter may not read another hunter's findings before it
  finishes; independence is what makes agreement meaningful.
- **Same stop rules.** Any unexpected effect stops that hunter, not just the
  wave; record it and check whether the target is still healthy.

If the harness cannot run parallel agents, run the same contracts sequentially.
Parallelism is an optimization; the contract is the requirement.

## Evidence contract

Write this before the hunter starts. A hunter that cannot fill it should not run.
The template below is the web/API form; the constants are the precondition, the
decisive evidence, the negative control, the capture path and hash, the budget
and the stop condition. Source and binary hunters keep those constants and
substitute the mode evidence:

- **Source:** pinned revision, file:line, entrypoint-to-sink call path, the
  missing or misplaced check, and the reviewer who will re-walk the path.
- **Binary:** binary hash, invocation and environment, minimal input plus hash,
  and the observed effect (crash, register/stack state, backtrace).

```markdown
## Evidence contract — H-007

- Hunter: <agent/model/tool and version>
- Principal: account A (user), session from environment
- Precondition: A owns invoice 41; B owns invoice 42; both exist
- Request(s): GET /api/invoices/42 with A's cookie; follow no redirects
- Negative control: GET /api/invoices/41 as A → 200 with A's data
- Positive signal: 200 with B's invoice number/amount and A's session
- Capture: redacted request + response, status, headers of interest, UTC time
- Storage: evidence/H-007/{request.txt,response.txt,meta.json}
- Redaction: Cookie, Authorization, Set-Cookie, account emails, card data
- Budget: 3 requests, 60 seconds
- Stop: 403/404, 401 after first try, 5xx, or any state change
- Verdict allowed: candidate / needs_validation only — never confirmed
```

The contract is also the handoff to the verifier. If the signal is real, the
verifier should be able to reproduce it from this contract plus the capture,
without reading the hunter's narrative.

## Signal classification

Classify every hunter result before the next wave. One label per result:

| Label | Meaning | Next action |
|---|---|---|
| `signal` | The expected evidence appeared and the negative control held | Promote to a candidate; send to a fresh verifier |
| `weak_signal` | Something is off but the evidence is incomplete | New hypothesis with a cheaper or sharper test |
| `noise` | Expected behavior, wrong assumption or an artifact of the test | Record and drop; do not retry unchanged |
| `duplicate` | Same root cause as an existing candidate | Merge into the canonical finding; keep the alias |
| `blocked` | Missing tool, account, permission, state or scope | Record the blocker and owner; try a fallback |
| `out_of_scope` | The test would cross a scope line | Stop that hunter; do not "just check" |

A hunter never writes `confirmed`. It writes a candidate with evidence and a
confidence note. Classification is a triage step, and the verifier makes the
final call.

## Stop and feed the next wave

Stop the loop when any of these is true:

- every ledger row is `covered`, `skipped` or `blocked` with a reason;
- the wave, request, time or cost budget is exhausted;
- two consecutive waves add no `signal` or `weak_signal`;
- the risk signal fires (instability, real user data, out-of-scope effect);
- the remaining hypotheses need an approval the run does not have.

Otherwise, feed the next wave:

1. Add the new signals and weak signals as ledger rows.
2. Mutate each weak signal into one sharper hypothesis (new operator, principal
   or path), not a repeat.
3. Re-rank prompt cards for the new rows; a card that produced only noise loses
   priority for this target, not permanently in the catalog.
4. Update `threat-model.md` and `state.json` with what was learned.
5. Keep the brute reserve closed unless the scope and the owner open it.

The output of the loop is not a pile of alerts. It is a small set of candidates
with reproducible evidence, plus an honest ledger of what was not tested.

Next: verification and reporting in [reporting.md](reporting.md).
