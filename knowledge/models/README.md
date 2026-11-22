# Model profiles

Advisory notes on choosing a model per role. `sak` never stores a key; only `sak hunt`
starts a child model through its runner. The other commands are deterministic.
these pages help a human or an agent harness pick a model and record the choice honestly.

| File | Contents |
|---|---|
| `profiles.md` | The four roles, what each needs, and the trade-offs. |
| `refusal-probe.md` | A small, repeatable refusal probe with a results table. |
| `operator-reports.md` | How we record an unverified operator claim, including the GPT 6.1 Terra note. |

Machine-readable cards live in `catalog/models.yaml`; `uv run sak catalog list` shows them with
the rest of the catalog.

The unit of advice is **the job**, not the brand: hunting, generation, verification, reporting.
A model that is excellent at one is usually the wrong price for another, and a model generation
change should only require editing a card, not a plan.
