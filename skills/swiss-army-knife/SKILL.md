---
name: swiss-army-knife
description: Authorized security assessment orchestration for web apps, APIs, source trees, binaries and LLM targets — written scope gate, ranked tool selection from the sak catalog, dry-run-first execution, threat-model-driven prompt hunters, independent verification and evidence-backed reporting. Use for security audits, pentests, bug-bounty triage, finding vulnerabilities, choosing or running security tools, or running the swiss-army-knife suite end to end.
license: MIT
---

# Swiss Army Knife

A disciplined way to point a ranked portfolio of security tools, skills and prompt
cards at an **authorized** target, keep the evidence honest, and stop on a budget
instead of on vibes.

The suite is the `sak` CLI plus its catalog. This skill is the operating layer: it
decides what to run, in what order, with which evidence, and what may be claimed
afterwards. It is portable: it assumes files, a shell and a model, not a specific
agent harness.

## When to use

Use this skill when the request is one of:

- a security audit, pentest, bug-bounty engagement or pre-release security review;
- "find vulnerabilities", "test this endpoint", "review this code for security",
  "is this input reachable", "check for IDOR/SSRF/XSS/authz gaps";
- tool selection: which scanner, fuzzer, secret scanner or prompt hunter to use,
  and in what order;
- running the swiss-army-knife suite (`sak`) or one of its plans, adapters or
  prompt cards;
- turning a pile of scanner output into verified findings and a report.

Do not use it to attack systems you do not own or have written permission to test,
to run destructive or denial-of-service payloads, or to process real user secrets.
Those are refusals, not configuration options. See
[references/safety.md](references/safety.md).

## Operating contract

1. **No scope, no action.** A run starts only after `runs/<run-id>/scope.md`
   names the allowed hosts, paths, methods, accounts and window. If the scope is
   missing or ambiguous, stop and ask; do not infer it from the request.
2. **Dry-run first.** Checks and dry runs are offline: they inspect tools,
   local configuration and the rendered command, and make no network request.
   Read-only target traffic is still active execution and needs the scope gate,
   `--execute` per step and a recorded reason.
3. **Verified cards only, automatically.** By default the planner auto-selects
   `status: verified` cards. `unverified` or `experimental` cards are manual,
   dry-run and explicitly approved. `deprecated` is never run.
4. **One evidence contract per hunter.** Every hunter gets a hypothesis, a
   cheapest test, expected evidence and a stop condition before it runs. A
   hunter may produce a candidate, never a `confirmed` finding.
5. **Read-only hunters in parallel; state changes serialized.** Parallelism is
   for GET/HEAD/OPTIONS and replays in separate accounts. Anything that writes,
   deletes, spends or sends is serialized, rate-limited and approved.
6. **The verifier is fresh and adversarial.** A separate context that sees the
   claim and the evidence pointers — not the hunter's reasoning — tries to
   disprove it. Reproduce from scratch; prefer a different principal and path.
7. **Budgeted waves.** Respect the role caps from the plan and the request,
   time, rate and cost budget from the scope. Stop when coverage is complete,
   the budget is spent, or two waves add no new signal.
8. **Evidence or it did not happen.** `confirmed` requires reproducible,
   mode-appropriate evidence: a redacted request/response plus controls for
   web/API, a pinned source location, reachable path and checked conditions for
   source, or a minimal input, environment and observed effect for binary.
   Otherwise the verdict is `needs_validation` or `rejected`.
9. **Never print or store secrets.** Redact tokens, cookies, authorization
   headers, keys and personal data in commands, logs, evidence and reports.
10. **The agent drafts; the human sends.** Reports and disclosures are prepared
    for a human owner. This skill has no send, publish or notify action.

## Workflow

1. **Intake and scope.** Confirm authorization, fill the scope and threat-model
   templates, pick the mode, accounts and budget, and create the run directory.
   → [references/workflow.md](references/workflow.md)
2. **Select the portfolio.** Use `sak plan` when the CLI is installed; otherwise
   route by hand from the catalog. Understand primary, support, fallback and
   brute roles before running anything.
   → [references/selection.md](references/selection.md)
3. **Execute by domain.** Web/API goes to Nuclei plus prompt hunters, source to
   the vendored `security-audit` skill, binary to `pwn-hunter`, OSINT to
   Blackbird/Webseek, LLM targets to the `LLM-*` cards. Engines are optional and
   explicit.
   → [references/selection.md](references/selection.md#execution-routing)
4. **Mutate and hunt.** Seed from the threat model, mutate bounded hypotheses,
   run read-only hunters in parallel, classify signals and feed new ones into
   the next wave.
   → [references/prompt-mutation.md](references/prompt-mutation.md)
5. **Verify and report.** Disprove first, dedupe by root cause, assign one of the
   three verdicts, and render the report artifacts.
   → [references/reporting.md](references/reporting.md)
6. **Learn.** Update rankings and prompt cards only from measured results, using
   the improvement-loop metrics.
   → [docs/improvement-loop.md](../../docs/improvement-loop.md)

Worked end-to-end examples: [docs/orchestration.md](../../docs/orchestration.md).

## Roles and budgets

| Role | Meaning | Default cap |
|---|---|---|
| `primary` | Highest-ranked verified tools that answer the main question | 3 |
| `support` | Narrower or cheaper helpers, second opinions | 4 |
| `fallback` | Reliable lower-scored substitutes when a primary is missing or fails | 3 |
| `brute` | Aggressive or high-noise reserve; requires explicit approval | 1 |

Prompt cards additionally use `triage` and `evidence` roles, which support a
wave rather than lead it. Caps are per suite; record any override in
`scope.md`.

## Stop conditions

Stop the run, write the blocker and next action, and hand back when:

- the target, host, account or window is outside `scope.md`;
- an action would be destructive, denial-of-service, or touch real user data;
- a step needs `--execute` without recorded approval;
- the request/time/rate/cost budget is exhausted;
- two consecutive waves add no new signal and the ledger has no open rows;
- a tool, credential or engine is missing and the fallback cannot cover it;
- the verifier cannot reproduce a claim and no cheaper test remains.

## References

| Reference | Use it for |
|---|---|
| [references/workflow.md](references/workflow.md) | Intake gate, scope and threat-model templates, budget, coverage ledger, run directory |
| [references/selection.md](references/selection.md) | `sak plan`, roles, verified-only auto-run, execution routing, manual catalog fallback |
| [references/safety.md](references/safety.md) | Authorization, forbidden actions, secrets, blast radius, stop rules |
| [references/prompt-mutation.md](references/prompt-mutation.md) | Seed → mutate → parallel hunt loop, evidence contract, signal classes |
| [references/reporting.md](references/reporting.md) | Verification, dedupe, verdicts, evidence standard, report artifacts, learn step |
| [references/sources.md](references/sources.md) | Provenance, command map, licenses and attribution |

## Provenance

MIT-licensed original text. Vendored MIT skills, external engines and upstream
methods keep their own licenses and provenance; see
[references/sources.md](references/sources.md) and `vendor/PROVENANCE.md`. No
GPL, AGPL or unlicensed code is vendored into this repository.
