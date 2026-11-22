# Choosing a model per role

Four jobs, four different cost and reasoning profiles. The cards in `catalog/models.yaml` name
the jobs (`hunt-cheap`, `gen-low-refusal`, `verify-high-effort`, `report-writer`) so a plan can
say "verifier = high effort" without pinning a vendor version that will be gone next quarter.

## hunting

What the role does: read the target (source, routes, responses), enumerate the attack surface,
prioritise boundaries and propose the next probe.

Needs: high throughput, a large context window, tolerance for messy input, low price.

Does not need: deep multi-step reasoning, long-term memory, tool use.

Trade-off: a cheap hunter produces more candidates per dollar but a higher duplicate and
false-positive rate. That is acceptable because the verifier filters; it is not acceptable if the
hunter's output goes straight into a report. Cap its output (for example, 5 candidate boundaries
per pass) so the verifier's budget is not consumed by volume.

Use `hunt-cheap`. Escalate a single hard question to the verifier rather than switching the whole
hunting wave to an expensive model.

## generation

What the role does: turn a boundary into concrete tests: payload variants, encodings, parser
tricks, multi-step request sequences.

Needs: low refusal rate on legitimate authorized-testing wording, format discipline, enough
creativity to escape a blocklist.

Does not need: a huge context window; the request is narrow.

Trade-off: refusal behaviour is the variable that decides whether a run stalls, and it is
**not** the same as model quality. A model that refuses the permitted step converts a coverage
gap into a `refusal` class in the improvement loop. A model chosen for low refusal can also be
less careful about scope, so the scope statement and the target allowlist must be in the request,
not in the model.

Use `gen-low-refusal`. If a generation stalls, record the exact step and try a narrower request or
the other profile before changing the whole plan; see the `refusal` row in
`docs/improvement-loop.md`.

## verification

What the role does: adjudicate a candidate. Is the boundary reachable? Is there a control that
differs by one variable? Does the evidence show impact, or only a suspicious string? Confirm,
hold for validation, or reject.

Needs: multi-step reasoning, careful reading of tool output, resistance to a persuasive hunter
summary.

Does not need: speed. This is the smallest call volume in the run.

Trade-off: the expensive model is worth it here because a wrong `confirmed` verdict is the most
costly error the product can make: it destroys precision and the report's credibility. Give the
verifier the raw evidence (requests, responses, source path), never the hunter's conclusion.

Use `verify-high-effort`.

## reporting

What the role does: turn confirmed findings, open questions and coverage gaps into a readable
report.

Needs: structure, concision, fidelity to the evidence pointer.

Does not need: creativity. It must not add a finding, raise a severity or drop a coverage gap.

Trade-off: a mid-cost model is usually enough; the failure mode is editorial (smoothing over a
gap) rather than analytical. Fix it with a schema and a checklist, not a bigger model.

Use `report-writer`.

## Two habits that matter more than model choice

1. **Record the model per role in run metadata.** A result without the model, provider, date and
   plan revision is not comparable to anything. `docs/improvement-loop.md` makes this a rule.
2. **Run the probe before trusting a low-refusal claim.** `refusal-probe.md` is deliberately
   small: three permitted requests against the local fixture and one clearly out-of-scope request
   that a model should refuse. It measures behaviour on this product's wording, not a vendor's
   safety benchmark.
