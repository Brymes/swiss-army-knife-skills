# Improvement loop

SAK is only useful if a change to a prompt, tool or plan can be shown to improve a
measurement. This document defines the eval metrics, the evidence standard and the update
loop. It is the rubric for T10's fixture eval and for any later prompt or adapter change.

The method follows the harness-engineering discipline: preserve a baseline, change one
variable, rerun the same task, and record the delta. A longer report, a lower severity or a
more cautious tone is not evidence of improvement.

## Eval set and ground truth

- **Target:** the local fixture in `tests/fixtures/vuln_app/` (T8), bound to `127.0.0.1`.
  It contains 14 seeded issues across the "bad guy" attack set and a set of safe endpoints.
- **Ground truth:** one record per seeded issue (identifier, boundary, expected evidence)
  and one record per safe endpoint that must stay clean. T10 owns the eval harness under
  `eval/`; the fixture owns the issues.
- **Revision pinning:** record the fixture revision, suite, plan, model and budget for every
  run. A result from a different revision or configuration is not comparable.
- **Reset:** restore known state before each run. Do not reuse mutated application data.
- **Offline:** the eval uses localhost only. No live external target, production data or
  real user account is part of the loop.

A run produces `findings.json`, `coverage-ledger.json`, evidence files, logs and run
metadata. The metrics below read those artifacts; none of them relies on the agent's own
summary of its work.

## Metrics

Report raw counts next to every rate. With a 14-issue fixture, one issue is 7.1 percentage
points; a rate without its denominator hides that.

### seeded-issue recall

Distinct seeded issues with a `confirmed` finding that cites evidence, divided by the
number of seeded issues (14).

```text
recall = |seeded issues confirmed with evidence| / 14
```

Source: `findings.json` joined to the ground-truth issue IDs. The v1 acceptance target is at
least 10 of 14. A `needs_validation` finding does not count as recalled, because recall is a
claim about demonstrated issues, not leads.

### confirmed precision

Confirmed findings that survive adjudication, divided by all confirmed findings.

```text
precision = |confirmed findings upheld on review| / |confirmed findings|
```

Source: `findings.json` plus a reviewer decision per finding. If there are no confirmed
findings, report `n/a` rather than 100%. The fixture target is 1.0: no confirmed finding on
a safe endpoint may survive review.

### trust-boundary coverage

Trust boundaries with at least one **executed** probe, divided by the boundaries enumerated
in the run's `threat-model.md`.

```text
coverage = |boundaries with ≥1 executed probe| / |boundaries in threat model|
```

Source: `coverage-ledger.json` and `threat-model.md`. A planned but unexecuted probe is not
coverage. A scope exclusion is counted as uncovered and listed as an explicit gap. The
target is 100% for in-scope boundaries, or a written justification for each gap.

### time to first signal

Wall-clock time from run start to the earliest candidate finding or evidence record. This
measures latency to a lead, not to a confirmed issue.

```text
time_to_first_signal = timestamp(first candidate/evidence) - timestamp(run start)
```

Source: run metadata start time and the first finding/evidence timestamp. If no signal is
produced, report `no signal` and the run duration; do not report zero. Use the same clock and
the same starting condition across runs.

### cost per finding

Total run cost divided by confirmed findings.

```text
cost_per_finding = (model token cost + billed tool/API cost) / |confirmed findings|
```

Source: provider usage in run metadata and adapter cost fields where available. If there are
no confirmed findings, report total cost and `n/a` for the per-finding value.

**Limitation:** the deterministic fixture eval makes no model calls, so it cannot produce
this metric. It is measured only on an agent-assisted run that records token and cost
metadata. The v1 fixture result should say `n/a (offline fixture)` rather than invent a
number. T10's eval may record it when an agent run is available; otherwise it remains a
manual measurement.

### duplicate rate

Candidate findings removed as duplicates, divided by all candidate findings before dedupe.

```text
duplicate_rate = |candidates removed by dedupe| / |all candidates|
```

Source: the dedupe log and `findings.json`. A high rate can mean noisy tools or a weak
fingerprint; a rate of zero can mean the fingerprint is too strict. Report the number of
distinct root causes as well, so a low rate is not mistaken for good dedupe.

### false-positive rate

Candidates judged not to be issues, divided by all candidates triaged. Report the
confirmed-only variant separately.

```text
false_positive_rate = |candidates rejected as false positives| / |all candidates triaged|
confirmed_false_positive_rate = |confirmed findings later shown false| / |confirmed findings|
```

Source: `findings.json` (`rejected` records with a reason) and reviewer adjudication. The
acceptance gate is **zero confirmed false positives on safe endpoints**, which is the
`confirmed_false_positive_rate` numerator, not the candidate-level rate. Always state which
denominator is used.

### Secondary measurements

These are useful but not acceptance gates: `needs_validation` rate, unresolved coverage-gap
count, time to confirm, evidence completeness (claims with a valid evidence path), tool
failure count, and human triage minutes.

## Measurement protocol

1. Freeze the fixture revision, suite, plan, model, provider and budget.
2. Reset the fixture. Confirm readiness with a harmless normal operation.
3. Run the baseline and save every artifact before changing anything.
4. Score with the ground truth prepared independently of the run.
5. Repeat a changed configuration at least twice when the change is nondeterministic; report
   both results and the variance.
6. Keep ties and regressions in the record. Do not delete a run that failed to improve.

Do not compare runs that differ in more than the variable under test. Do not tune the ground
truth after seeing the result. A small fixture cannot support a general claim about model or
product quality; phrase conclusions narrowly.

## Update loop

### 1. Run

Execute the same command on the pinned eval set, for example:

```sh
uv run pytest tests/test_fixture.py -q
python3 eval/run_fixture.py
uv run sak report runs/demo
```

Save the artifacts under a run directory and record the command, revision and configuration.

### 2. Triage

Dedupe candidates, assign one of `confirmed`, `needs_validation` or `rejected`, and check
that each verdict has an evidence path. A `needs_validation` record keeps its open question
and next action. Never promote a record to `confirmed` to make the report look complete.

### 3. Classify misses

For every seeded issue not confirmed, assign one cause from this taxonomy. "The model was
not good enough" is not a cause.

| Class | Meaning | Typical change |
|---|---|---|
| `no-tool` | No selected tool or prompt can test the boundary | Add a card, adapter or hunter |
| `tool-failed` | The right tool ran but crashed, timed out or was missing | Fix the adapter, install hint or budget |
| `prompt-miss` | The hunter did not ask for the relevant condition | Mutate the prompt card |
| `context-miss` | The needed source, account or fact was not in context | Add context or an oracle |
| `scope-excluded` | The boundary was outside the authorized scope | Record the gap; do not silently expand scope |
| `parse-miss` | Output contained the signal but the parser lost it | Fix the parser and add a fixture case |
| `dedupe-loss` | A true issue was merged into another root cause | Fix the fingerprint or merge rule |
| `verifier-reject` | A true candidate was rejected by verification | Fix the verifier prompt or evidence rule |
| `refusal` | The model declined the permitted step | Record the blocker; try another role/model or a narrower request |
| `fixture-drift` | The fixture no longer represents the expected issue | Fix the fixture or the ground truth, with review |

### 4. Change one variable

Pick one change that addresses the dominant class: mutate one prompt card, add one tool,
fix one parser, add one piece of context, or add an oracle. Record the hypothesis before
running: "Changing X should raise metric Y from A to B because Z." Do not bundle a prompt
change, a plan change and a parser change in the same comparison.

Prompt mutation follows the existing library: keep the stable card ID, version the change,
and review it like code. A prompt edit without an eval delta is an unreviewed change.

### 5. Rerun

Rerun the **same** eval set, command and budget. A change that only works on a new target or
a different suite has not been evaluated.

### 6. Record the delta

Write one row per change. Keep the baseline and the candidate side by side.

| Run | Change | Recall | Confirmed precision | Boundary coverage | Time to first signal | Cost/finding | Duplicate rate | FP rate | Verdict |
|---|---|---|---|---|---|---|---|---|---|
| baseline | none | | | | | | | | keep |
| candidate | one change | | | | | | | | keep / revert / tie |

Verdict rules:

- **keep** — the target metric improved without a material regression in another gate.
- **revert** — the metric did not improve, or another gate regressed.
- **tie** — the result is indistinguishable; keep the simpler version and record the tie.

A change that improves one metric while increasing false positives, duplicates or cost is
not automatically an improvement. State the trade-off.

## Evidence standard

A finding needs at least one of:

1. a **reproduction** — the smallest request or command, the observed response, and a
   control that differs by one variable;
2. a **source trace** — file, function and call path that reaches the claimed boundary,
   with the conditions that make it reachable; or
3. an **observed result** — a tool or runtime observation that directly shows the claimed
   behaviour, plus the target-state check.

Every claim names its evidence path and the test or command that produced it. A claim
without a path is a lead, not a finding.

- **Stale evidence is not evidence.** If the target revision, configuration, account or
  dependency changed, rerun or downgrade the claim.
- **Unresolved evidence is not coverage.** A `needs_validation` record with an open question
  is honest, but it does not count toward recall, precision or boundary coverage.
- **Negative evidence is scoped.** "The request returned 403 under these conditions" does
  not establish that no bypass exists on another path. Record the tested condition and the
  untested alternatives.
- **A model statement is not evidence.** Agent prose, a severity score or a confident
  explanation is an interpretation. The evidence is the request, source path or observed
  result behind it.
- **Evidence records are immutable in substance.** Each record carries an ID, target
  revision, configuration, principal, request/command, observed output, state check,
  timestamp, producer and a content hash. A later interpretation may change the finding's
  status; it does not rewrite what was observed.
- **Confirmed means evidenced.** `confirmed` requires evidence and, where applicable, a
  control. `needs_validation` requires an open question and a next action. `rejected`
  requires a reason.

## Anti-pattern checklist

Run this list before accepting an eval result or a report.

| Anti-pattern | How to detect it | Required fix |
|---|---|---|
| Unbounded exploration | No wave budget, request cap, time cap or stop condition; the run keeps adding targets | Bound the plan; record the budget; stop on coverage or budget exhaustion |
| No coverage ledger | The report cannot say which boundaries were not tested | Maintain `coverage-ledger.json`; list gaps explicitly |
| Treating a model claim as proof | The finding cites agent prose or a CVSS score but no request, source trace or observed result | Add evidence; downgrade to `needs_validation` until it exists |
| Duplicate root causes | Several findings share an asset, entrypoint and root cause but different wording | Dedupe by fingerprint; report distinct root causes |
| Severity inflation | High severity with assumed preconditions, no demonstrated impact or an untested attack path | Separate confidence from severity; score only demonstrated impact |
| Live-target drift | Results mix revisions, configurations or dates; a current claim rests on an old observation | Pin the revision and configuration; rerun against the current target |
| Unreviewed prompt changes | A prompt card changed without a version note, review or eval delta | Version the card; rerun the eval; review the change like code |

Two related failure modes are worth catching in the same pass: a **silent tool failure**
(the adapter reports success but scanned nothing) and **metric gaming** (improving a rate by
weakening the ground truth or narrowing the denominator). The first is a coverage gap; the
second invalidates the comparison.

## Reporting a loop result

Keep the summary short and auditable:

```text
Baseline: <command>, <revision>, <suite>, <model>, <budget>
Result: recall X/14, precision Y, boundary coverage Z/W, first signal T, cost C, duplicates D, FP F
Misses: <issue id> — <class> — <evidence>
Change: <one variable> — <hypothesis>
Candidate: <same command and configuration>
Delta: <metric before → after>; regressions: <none or list>
Decision: keep | revert | tie, because <reason>
Limits: <small n, fixture-only, cost n/a, unresolved gaps>
```

A supported hold, a precise blocker or a refuted hypothesis is a successful result. The goal
is an inspectable method, not a promised vulnerability.
