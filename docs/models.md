# Models — selection guidance

`sak` does not call a model. It selects work, records evidence and produces a report; a human or an
agent harness runs the model. This page is about choosing one per role, recording the choice, and
not confusing a good model with good evidence.

Model cards: `catalog/models.yaml` (`uv run sak catalog list --kind model`). Deeper notes:
`knowledge/models/`.

## The four roles

| Role | Card | What the model does | What matters | What does not |
|---|---|---|---|---|
| hunting | `hunt-cheap` | Reads source and responses, enumerates the surface, proposes the next probe | Price, speed, context size | Deep reasoning |
| generation | `gen-low-refusal` | Turns a boundary into payload variants and test sequences | Refusal behaviour on authorized wording, format discipline | Huge context |
| verification | `verify-high-effort` | Adjudicates a candidate against its evidence: confirm, hold or reject | Multi-step reasoning, care with controls | Speed |
| reporting | `report-writer` | Writes the report from confirmed findings and gaps | Structure, fidelity to evidence paths | Creativity |

One model rarely wins two roles. The usual split is a cheap hunter and reporter around an
expensive verifier, with a generation model chosen by probe rather than by reputation.

## Selection in practice

1. **Start from the plan, not the vendor.** A suite names roles and budgets; a model choice fills a
   role. If a plan has three primary hunters, hunting is the cost centre — optimise there first.
2. **Run the refusal probe before a generation wave.** `knowledge/models/refusal-probe.md` takes
   minutes. A model that refuses a permitted payload request turns into a `refusal` coverage gap
   mid-run, which is a worse outcome than a slightly weaker model that complies.
3. **Give the verifier evidence, not summaries.** Pass the request/response pair, the source path
   and the control. A verifier that only sees the hunter's prose will agree with it.
4. **Record the served model.** Run metadata needs the provider, model identifier, date, role and
   plan revision. `gpt-5` and `gpt-5-2026-11-01` are not the same measurement.
5. **Change one variable.** If you swap the verifier and edit the prompt in the same run, the delta
   in `docs/improvement-loop.md` means nothing.

## Expect to be refused, and record it

A refusal on a permitted step is data. Record the exact step, the role and the model, classify it
`refusal` in the improvement loop, then either narrow the request (one boundary, explicit
authorization and scope, a smaller artifact) or move that step to a model that passes the probe.

Do not disguise a request to get past a safety check. The probe's fourth task exists to catch the
opposite failure: a model that will happily work outside the stated scope. That result disqualifies
the model for sak, no matter how capable it looked on the other three.

## Cost and budget

- Hunting is the token sink: it reads whole repositories. Set an output cap per pass so a cheap
  model does not flood the verifier.
- Verification is low volume, high value. Spend there.
- Reporting is mid volume. A structured template (`REPORT.md`, `FINDINGS-DETAIL.md`,
  `NEEDS-VALIDATION.md`) does more for quality than a bigger model.
- A full engine run (PentAGI, ARTEX, T3MP3ST) adds its own model bill and its own provider keys;
  see `docs/engines.md`. Engines are optional for this reason.

## Privacy and secrets

- Hosted models receive whatever you paste. Send fixture data or redacted source, never a real
  credential, cookie or personal record.
- Keep keys in the environment or an engine's `.env` under `vendor/external/`. They never belong in
  a card, a prompt, a run log or a report.
- Run the probe against the local fixture only. `tests/fixtures/vuln_app` is authorized; a real
  third-party system is not.

## The operator note

The operator named a model as GPT 6.1 Terra. That is recorded as **OPR-01, an unverified operator
report whose exact source text is still pending** (`knowledge/models/operator-reports.md`) and as
the card `gpt-6.1-terra` with `status: unverified`. No capability or usefulness claim is attached,
and the probe table has `not run` for it. Treat it as a name to test, not a recommendation, and
never as evidence about a target.

## What we still do not have

- No measured refusal rate for any model in this repository.
- No cost-per-finding measurement: the offline fixture eval makes no model calls, so
  `docs/improvement-loop.md` reports `n/a (offline fixture)` for that metric.
- No benchmark comparison between models; a 14-issue local fixture is too small to support one.

Those gaps are deliberate and better than an invented number.
