# Operator reports

An operator report is something a human told us that we have not tested. It is recorded because it
is useful context for the next run, and labelled so nobody mistakes it for evidence.

Rules:

1. Record the reported text (or the reported name) without adding claims the source does not make.
   If the exact wording is missing, say so and do not paraphrase a capability or a preference.
2. Name the date and the source as far as the record allows.
3. Mark the model card `status: unverified`.
4. Add a `not run` row to `refusal-probe.md` so the gap is visible in the results table.
5. Promote a report to a recommendation only after a recorded probe or eval run. The promotion is
   a new entry; never edit the original note.

## OPR-01 — GPT 6.1 Terra (2026-11-08, operator)

**Recorded:** the operator named a model as "GPT 6.1 Terra".

**Source text:** not available in this repository. The senior has requested the operator's exact
wording; until it arrives, this record carries the name only.

**What we know:** only the name the operator used. We have not confirmed the served model
identifier, the provider route, availability, price, context window, tool-calling behaviour or
refusal behaviour. We make no claim about what the model is good at.

**What we have not done:** no refusal probe, no fixture eval, no comparison run. The row in
`refusal-probe.md` therefore says `not run` for every task.

**How to use it today:** as a name to test if you have access. Run `SAK-REFUSAL-01` twice, record
the exact served identifier, and add the rows. Only then can the `gpt-6.1-terra` card carry a
measured note; that is a new record, not a rewrite of this one.

**What it must never become:** a claim in a client report, a severity input, or a reason to skip
verification. A model name is not evidence about a target.

## Template

```text
OPR-NN — <model as named> (<date>, <who>)
Recorded: <the reported text, or the name if the text is missing>
Source text: <available | pending, and who was asked>
What we know: <facts only>
What we have not done: <probes, evals, comparisons>
How to use it today: <role hypothesis, or "test before use">
What it must never become: <over-claims to avoid>
```
