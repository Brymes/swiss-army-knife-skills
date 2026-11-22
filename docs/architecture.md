# Architecture

`sak` is a small, file-based system. The catalog describes what can run, the
planner ranks a bounded subset, the runner performs one step at a time, and the
findings and report layer keep evidence honest. There is no database, daemon or
control plane.

## Layers

```text
catalog/*.yaml + schemas/*.schema.json
        |
        v
  sak catalog  validate / list / show / search / export
        |
        v
  sak plan     filters -> score -> roles -> waves -> plan.json
        |
        +--> sak prompts   prompt cards -> hypotheses -> rendered briefs
        |
        v
  sak run      one adapter step (dry run by default) -> evidence + logs
        |
        v
  sak findings status, dedupe, evidence hashes -> findings.json
        |
        v
  sak report   REPORT.md / FINDINGS-DETAIL.md / NEEDS-VALIDATION.md
```

`sak doctor`, `sak engine` and `sak eval` sit beside that path: doctor is a host
inspection, engine is an explicit optional side path, and eval drives the
localhost fixture through the same findings and report contracts.

## Modules

| Module | Responsibility |
|---|---|
| `src/sak/catalog.py` | Discover YAML, infer card type, validate against schema, detect duplicate IDs, resolve suite references, query and export |
| `src/sak/plan.py` | Hard filters, ranking formula, role assignment, waves, exclusion reasons, optional `plan.json` |
| `src/sak/doctor.py` | Inspect Python, uv, git, node, nuclei, docker, pwntools and friends; print install hints; never install |
| `src/sak/prompts.py` | Load prompt cards, parse a Markdown threat model, bound mutations, render hunter briefs and hypotheses |
| `src/sak/run.py` | Resolve one plan step, enforce scope and budget, call an adapter with `--dry-run`/`--execute`, write evidence and logs |
| `src/sak/findings.py` | Fingerprints, status transitions, dedupe, evidence hashing and masking, document/ledger validation |
| `src/sak/report.py` | Render reports; recompute confirmed counts and coverage from verified evidence |
| `src/sak/eval.py` | Start the loopback fixture, run deterministic positive probes and negative controls, record metrics and optional artifacts |
| `src/sak/engine.py` | Operate optional external engine cards; dry run unless executed |

`src/sak/__main__.py` registers the stable command surface:
`catalog`, `plan`, `doctor`, `engine`, `prompts`, `run`, `findings`, `report`
and `eval`. Optional modules are imported lazily so a partial build still starts.

## Catalog

Catalog YAML is the source of truth. `load_catalog` walks `catalog/` recursively,
loads every `*.yaml`/`*.yml` file, infers the card type from the directory name
(`tools/`, `prompts/`, `suites/`, `sources/`, `engines/`, `models.yaml`) and
validates each card. Cards may be a single mapping, a list, or a mapping under a
plural key.

Four invariants matter:

1. **IDs are unique across the whole catalog.** `validate_catalog` reports every
   duplicate with all source paths.
2. **References resolve.** A suite's `include.tools`, `include.prompts` and
   `filters.exclude_ids` must name existing cards. A broken reference is a
   validation error, not a silently empty plan.
3. **Only `verified` is automatic.** When a suite omits `filters.statuses`, the
   planner allows only `verified` cards. `experimental` and `unverified` cards
   need an explicit suite entry and human approval.
4. **The catalog is read-only at run time.** Planning and execution never rewrite
   a card. Generated indexes do not exist; if one is added later, it must be
   generated, never hand-edited.

## Planning

The planner applies hard filters first: included tool IDs, excluded IDs, status,
kind, domains, modes, tags and runtime requirements. A card excluded here carries
a reason in the plan's `excluded` array.

Eligible cards are split into a regular pool and a brute reserve. The regular
pool is sorted by descending score with ID as the tie-break:

```text
score = 2*impact + reliability + stealth - effort - noise
```

Role caps then consume that order: `primary`, `support`, `fallback`; the brute
reserve is capped separately. The plan emits one wave per non-empty role. The
JSON document records `run_id`, target, suite summary, filters, candidates with
their score breakdown, roles, waves and exclusions, so a reader can explain the
selection without rerunning anything.

Suites also describe their operational waves — passive, broad, targeted, brute
and verify — in the card's `notes`. The schema deliberately has no executable
wave field: waves are a human/agent operating contract, while role waves are the
planner's bounded selection. Keeping the two separate prevents a YAML edit from
silently changing execution order.

## Run directories

A run directory is the evidence unit:

```text
runs/<run-id>/
  scope.md              written authorization and limits (required for --execute)
  plan.json             the ranked portfolio
  threat-model.md       assets, trust boundaries, invariants
  findings.json         verdicts and evidence records
  coverage-ledger.json  boundaries, probes and evidence
  run-metadata.json     target, suite, revision, operator, budget, usage
  evidence/             immutable request/response, logs, observations
  logs/                 tool and fixture output
  REPORT.md             rendered summary
  FINDINGS-DETAIL.md    every record and its evidence table
  NEEDS-VALIDATION.md   open leads and blocked claims
```

`runs/` is gitignored except `runs/.gitkeep`. Demo and eval artifacts are
generated; they are not committed. That is intentional: evidence belongs to the
engagement, not to the tool's history.

## Evidence and verdicts

Every evidence record has an ID, kind, path, SHA-256, timestamp and producer. The
report recomputes the hash and classifies each record as `verified`, `missing` or
`hash mismatch`.

A finding is one of:

- `confirmed` — evidence is present and every evidence record verifies;
- `needs_validation` — an open question and next action are required;
- `rejected` — a reason is required.

A record that is `confirmed` in `findings.json` but whose evidence is missing or
changed is **not** counted as confirmed, recall or verified coverage. It appears
under "confirmed claims excluded from counts". This is the core anti-hallucination
rule: the report cannot be improved by editing a claim, only by attaching
reproducible evidence.

Fingerprints are SHA-256 over normalized `asset`, `entrypoint`, `root_cause`,
`principal` and `resource`. Wording, severity, status and evidence do not affect
the fingerprint, so two tools that report the same root cause collapse. Dedupe
keeps the highest-confidence record and logs the removed ones.

Coverage is derived, not asserted. A trust boundary is covered only when an
executed probe has at least one verified evidence record. Planned probes,
exclusions and unverified probes become named gaps. The evaluation records the
positive probe and its safe control as two separate boundaries, so a probe that
raises before a meaningful observation cannot ride on its pair's evidence: it is
stored as `executed: false`, the boundary is `uncovered`, and the problem is
named in the gap. Failed controls are false positives in the precision formula;
control and probe exceptions are separate error counts. Any false positive,
control error or probe error makes the acceptance threshold fail.

## Determinism and offline defaults

- The planner is deterministic for a fixed catalog, suite, target and host tool
  set. Ties break on ID; timestamps only affect `run_id` and `generated_at`.
- The fixture seeds a fixed SQLite database and resets its cache epoch so a stale
  process cache cannot leak between probes.
- The eval harness runs one probe at a time and resets between probes. The only
  concurrency is the deliberate two-thread credit race, which is the issue under
  test.
- The demo chooses its loopback port before writing scope, plan or metadata and
  passes that exact port to the evaluation. An explicitly requested busy port is
  refused before any probe, so a run cannot report one target under another
  target's scope.
- The optional agent runs inside the live fixture lifecycle, after a
  deterministic reset, and the fixture is terminated on success, failure or
  timeout. Agent command and stderr are masked at the capture boundary and the
  command runs without a shell, so placeholder paths cannot become shell code.
- Adapters print commands unless `--execute` is passed. Engines require
  `--execute`. Deterministic `sak eval` and the demo never leave loopback and
  never call a paid model; their recorded cost is `$0.00`. An optional external
  agent may use network or a paid model; its cost is recorded as `null`, not
  asserted as zero.
- Tests are offline. The only network is loopback HTTP to the local fixture.

## Extension points

- **New tool or skill** — add `catalog/tools/<id>.yaml`; validate; smoke-plan.
- **New suite** — add `catalog/suites/<id>.yaml`; document waves, parallelism,
  budget and stop conditions in `notes`; validate and plan.
- **New prompt** — add a card under `catalog/prompts/`; keep the ID range
  documented in `catalog/README.md`; test expansion with a threat model.
- **New adapter** — add a module under `adapters/`, register its name in the tool
  card, support `--dry-run`, enforce scope before any request, and sanitize
  output. See [adding-tools.md](adding-tools.md).
- **New engine** — add an engine card with install/up/down/status commands and
  requirements; keep it external and gitignored unless the license allows
  vendoring.

Schema changes are contracts. Do not add an executable field to a suite or a
finding without updating the schema, the tests and every consumer together.

## Failure modes

| Failure | Behaviour |
|---|---|
| Invalid card or duplicate ID | `sak catalog validate` exits `1`; planner refuses to plan |
| Suite references an unknown card | Validation error with the suite ID and reference |
| Required host tool missing | Card excluded with `missing requirement: <name>`; `doctor` prints the hint |
| Missing scope | `sak run --execute` refuses before the adapter runs |
| Adapter needs network without approval | Refusal, not an implicit allow |
| Evidence moved or edited | Report marks it invalid and excludes the claim |
| Fixture port busy | Demo picks a free port before writing artifacts; an explicit busy `--port` is refused before probing |
| Report on a directory without findings | Warning and an empty report; it never fabricates records |
