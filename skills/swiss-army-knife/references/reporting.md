# Verification and reporting

A candidate is a claim. Verification decides whether the claim survives; the
report tells the truth about what survived and what did not. Nothing in this
step may be skipped because a finding "looks obvious".

## Verification

Verification is a fresh, adversarial pass, not a second opinion from the same
context.

- **Fresh context.** Use a new session or agent with the `VER-01` verifier
  prompt. It receives the target, the claim, the evidence pointers and the
  evidence contract. It does not receive the hunter's reasoning, confidence or
  chat history.
- **Try to disprove.** The verifier's job is to make the finding false: wrong
  principal, cached response, fixture data, another user's legitimate share,
  behavior already documented as intended, a test artifact. It must attempt at
  least one alternative explanation.
- **Reproduce from scratch.** Re-run the minimal test from the written contract:
  a request for web/API, a path walk for source, an input for binary. Do not
  reuse the hunter's session, shell history or captured response as proof.
- **Change one variable.** A different account, object ID or path for web/API; a
  different entrypoint, caller or guarded sibling for source; a different input,
  length or mitigation for binary. A finding that only works once, with one
  input, in one order, needs that condition stated.
- **Check the negative control.** If the control fails, the test is invalid, not
  the finding confirmed. Rerun the control before believing the signal.
- **Respect scope.** A verifier may not widen the test to "prove impact". If the
  real impact needs an out-of-scope action, the verdict stays
  `needs_validation` with the blocker recorded.
- **Record the attempt.** The verifier writes what it tried, what it observed,
  the commands and the capture hash. A failed disproof attempt is evidence too.

A verifier that only re-reads the hunter's evidence has not verified anything.

## Dedupe

Dedupe by **root cause**, not by URL, payload or scanner template. Two findings
that share a root cause are one finding with aliases.

Fingerprint fields:

| Field | Example |
|---|---|
| `asset` | `app.example.test` |
| `entrypoint` | `GET /api/invoices/{id}` |
| `root_cause` | missing ownership check in `invoice_get()` |
| `principal` | `user A` |
| `resource` | `invoice` owned by `user B` |

Rules:

- Same fingerprint → merge. Keep the clearest reproduction, keep every affected
  location or input as an alias (URL/parameter, source location, binary input),
  and keep the highest demonstrated impact.
- Different entrypoints with the same root cause → one finding, multiple
  locations. The report lists the locations; the count is not inflated.
- Same entrypoint with genuinely different causes → separate findings. Say why.
- A rejected duplicate is recorded as `rejected` with a pointer to the canonical
  finding, not deleted. The coverage ledger keeps both rows.
- Dedupe again after verification; a verifier may discover that two candidates
  share a cause, or that one "duplicate" does not.

## Verdicts

Exactly three verdicts, and only these:

| Verdict | Meaning | Requirements |
|---|---|---|
| `confirmed` | Reproduced independently with evidence; the impact is demonstrated within scope | Fresh verification, mode-appropriate evidence, negative control, stated precondition, no unresolved contradiction |
| `needs_validation` | Plausible but not yet reproduced, or blocked by access, state, tooling or scope | Written claim, partial evidence, exact blocker, next action and owner |
| `rejected` | Not reproducible, expected behavior, false positive, out of scope, or a duplicate of a rejected claim | Reason, what was tried, and a pointer to the evidence or duplicate |

`confirmed` is not a severity and not a promise to disclose. It means the claim
survived an attempt to disprove it. A finding may be `confirmed` and still be
low impact or already known; the report says so.

Severity and impact are separate from the verdict. Use the engagement's scale,
state the demonstrated impact (what an attacker gains), and do not inflate it
with a hypothetical chain that was not tested.

## Evidence requirements

Every `confirmed` finding carries an evidence package shaped by the assessment
mode. The common items come first; the decisive evidence differs because a
source or binary finding has no HTTP exchange to show.

| Item | Requirement |
|---|---|
| Reproduction | Minimal steps, commands or harness, in order, with the precondition |
| Mode evidence | See "Decisive evidence by mode" below |
| Negative control | The paired test that should not show the effect, and did not |
| Identity | Web/API: principal and provisioning. Source: pinned revision and reviewer. Binary: binary hash, libc, ASLR and host |
| Time | UTC timestamp of capture |
| Tool provenance | Tool and version, template/rule ID, prompt card ID, model if used |
| Integrity | SHA-256 of each evidence file; stored under `evidence/<finding-id>/` |
| Scope proof | The scope row that authorizes the asset and method |
| Redaction | Secrets, tokens, cookies and personal data removed; note what was removed |

### Decisive evidence by mode

- **Web / API:** the redacted raw request and response for the decisive exchange
  (status line, relevant headers and a body excerpt), the session or principal
  used, and a negative control that repeats the request without the missing
  condition.
- **Source:** repository URL plus pinned commit, file and line range, the
  reachable call path from entrypoint to sink, and the exact check that is
  missing or misplaced. An independent reviewer walks the path from the
  entrypoint, not just the sink. A source-only conclusion stays limited to what
  the source proves: if reachability or the runtime condition cannot be shown,
  the verdict is `needs_validation`. Never fabricate a request, response or
  runtime observation to fill the web/API template.
- **Binary:** the binary hash, architecture, loader/libc, mitigation state, ASLR
  setting and exact invocation; the minimal input (file or hex, plus its hash);
  and the reproducible observed effect (crash type, register or stack state,
  backtrace). An exploit claim beyond the observed effect is `needs_validation`
  unless a local proof is captured.

`needs_validation` carries what exists: the claim, the partial evidence for its
mode, the blocker, the next test and the owner. `rejected` carries the reason and
the attempt, so a later session does not repeat it.

No screenshot-only evidence for a confirmed web finding unless the response is
otherwise unrepresentable; if a screenshot is used, hash it and pair it with the
text capture. No mode-appropriate evidence, no `confirmed`.

## Report artifacts

The run directory is the report source. `sak report runs/<run-id>` renders the
three artifacts; if the command is unavailable, write the same three files by
hand from the ledger and findings.

| Artifact | Audience | Contents |
|---|---|---|
| `REPORT.md` | Owner, stakeholders | Scope, method, summary table of confirmed findings, severity, coverage and gaps, before/after remediation table, disclosure notes |
| `FINDINGS-DETAIL.md` | Engineers | One section per finding: impact, reproduction, evidence links, root cause, remediation, references |
| `NEEDS-VALIDATION.md` | Next session, owner | Open claims, exact blockers, next test, owner, budget remaining, rejected duplicates |

Report rules:

- Lead with the confirmed findings and their demonstrated impact. Separate facts,
  inferences and unknowns explicitly.
- Include the coverage ledger summary and every untested or blocked area. A
  report that hides its gaps is misleading, even if every finding is true.
- Include the before/after table: what was exploitable at the tested revision,
  what the fix changed, and how it was re-tested.
- Link evidence by relative path plus hash; never paste raw secrets or full
  personal records.
- State the tested revision, environment, date, suite/plan and model. A result
  without provenance is not reproducible.
- The human owner decides on disclosure and sends it. The agent drafts; it does
  not email, publish or notify the target.

## Learn

The last step is measurement, not storytelling. Use the improvement loop in
[docs/improvement-loop.md](../../../docs/improvement-loop.md): seeded-issue
recall, confirmed precision, trust-boundary coverage, time to first signal, cost
per finding, duplicate rate and false-positive rate.

Update only from observed results:

- **Rankings.** If a card was reliable and cheap on this class of target, its
  `reliability` or `effort` may move. If it produced noise, move it down. Edit
  the card YAML, run `sak catalog validate`, and record the evidence for the
  change. Never hand-edit a generated index.
- **Prompt cards.** Add the mutation operator, evidence requirement or stop
  condition that made a difference. Remove a mutation that only produced noise.
  Keep the card's ID stable; bump content, not identity.
- **Suites and budgets.** If a wave consistently runs out of budget before
  coverage, change the budget with a measured reason, not a feeling.
- **The report.** Record the change and the delta in the next run's metadata, so
  the next comparison is like-for-like.
- **The negative result.** A tool or prompt that found nothing on a class where
  it should have is a learning item, not a reason to lower the bar.

One variable at a time. A change that cannot be compared to a baseline is not an
improvement.

Next: provenance and command map in [sources.md](sources.md).
