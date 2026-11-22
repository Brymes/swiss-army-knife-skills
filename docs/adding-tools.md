# Adding tools, prompts and suites

The catalog is the extension surface. Most additions are one YAML file plus
`uv run sak catalog validate`. Code is only needed for a new adapter or engine.

Rules that do not change:

- Catalog YAML is the source of truth; generated indexes are never hand-edited.
- One card per file, one unique ID across the whole catalog.
- Validate before planning. A broken suite reference fails the whole catalog gate.
- Do not vendor GPL, AGPL or unlicensed code. MIT skills may be linked by
  `install.sh`; everything else stays external and gitignored.
- No secrets in cards, tests, logs, evidence or reports.

## Add a tool or skill card

Create `catalog/tools/<id>.yaml`. Required fields: `id`, `name`, `kind`,
`status`, `description`, `domains`, `phases`, `intensity`, `ranking`.

```yaml
id: example-scanner
name: Example HTTP scanner
kind: cli                 # skill | cli | platform | service | reference | mcp
status: unverified        # verified | unverified | experimental | deprecated
description: One sentence on what it finds and when to use it.
domains:
  - web
  - api
phases:
  - scan
  - verify
modes:
  - blackbox
  - greybox
intensity: normal         # passive | normal | brute
roles:
  - support
requires:
  - example-scanner       # executable name, python module, docker compose or ENV_VAR
ranking:
  impact: 4
  reliability: 4
  stealth: 3
  effort: 2
  noise: 2
install:
  manager: go
  command: go install example.com/example-scanner@latest
adapter: null             # set to an adapter name only if one exists
safety:
  active: true
  intrusive: false
  destructive: false
  notes: Dry run by default; execution needs scope.md and --execute.
license: Apache-2.0
sources:
  - url: https://example.com/example-scanner
    license: Apache-2.0
    note: External binary; not vendored.
notes: |
  Strengths: fast HTTP checks.
  Weaknesses: noisy on large scopes.
  Integration: external CLI; no vendoring.
```

Notes on the fields:

- `kind: skill` means an agent skill, usually one linked by `install.sh`. Set
  `adapter: null`; a skill is operated by the agent, not by `sak run`.
- `requires` is a hard host gate for the planner. Missing requirements exclude
  the card unless `--allow-missing-requires` is passed. `sak doctor` prints the
  hint for a missing requirement it knows.
- `intensity: brute` puts the card in the reserve regardless of its score.
- `ranking` uses integers `1..5`. Higher `effort` and `noise` reduce the score.
- `status: verified` means the card is safe to auto-select. Do not mark a card
  verified until its dry run, parser and safety notes are tested.

Then:

```sh
uv run sak catalog validate
uv run sak plan --suite web-blackbox --target http://127.0.0.1:8765 \
  --allow-missing-requires
uv run sak catalog show example-scanner
```

Check that the card appears in the expected role, or in `excluded` with a reason
you can explain. A silent absence is a bug.

## Add a suite

Create `catalog/suites/<id>.yaml`. Required: `id`, `name`, `description`,
`profile`, `filters`.

```yaml
id: web-blackbox
name: Web black-box
description: Authorized web/API assessment without source access.
profile: web-blackbox     # web-blackbox | web-source | binary | api-blackbox | custom
domains:
  - web
  - api
filters:
  kinds: [cli, skill, platform]
  statuses: [verified]
  domains: [web, api]
  modes: [blackbox, greybox]
  exclude_ids: []
include:
  prompts: [VIBE-01, VIBE-02, VER-01, REP-01]
budget:
  primary: 3
  support: 4
  fallback: 3
  brute: 1
targets:
  default_port: 8765
  scope_required: true
notes: |
  Roles: primary, support, fallback, brute.
  Waves:
    passive: ...
    broad: ...
    targeted: ...
    brute: ...
    verify: ...
  Parallel: ...
  Stop conditions: ...
```

Design checklist:

1. **Filter honestly.** A suite should not mix source and binary cards unless
   both are really in scope. `filters.statuses` defaults to `verified` only when
   omitted; listing `experimental` is a deliberate approval, not a shortcut.
2. **Budget the roles.** `primary` leads, `support` widens, `fallback` covers a
   failed primary, `brute` is a reserve. Set `brute: 0` when the domain has no
   brute phase (source, OSINT, LLM).
3. **Name the waves.** The schema has no executable wave field. Document the
   passive, broad, targeted, brute and verify waves, parallelism and stop
   conditions in `notes`. The planner emits role waves; the notes are the
   operating contract for those waves.
4. **Resolve references.** Every `include.tools`, `include.prompts` and
   `exclude_ids` entry must exist. `catalog validate` fails otherwise.
5. **Check the plan.** `sak plan --suite <id> --target <fixture>` should produce
   the roles you intended, and every exclusion should have a reason you accept.

## Add a prompt card

Create or extend a file under `catalog/prompts/`. Required: `id`, `title`,
`category`, `description`, `domains`, `hunter_role`, `prompt`.

```yaml
id: CUSTOM-01             # illustrative; pick the next free ID in a real range
title: Example business-logic invariant
category: vibe            # invariant | vibe | ssrf | llm | mutation | verification | report | orchestration
description: A cheap test for one client-trust assumption.
domains: [web, api]
hunter_role: support      # primary | support | fallback | brute | triage | evidence
applies_to: [web-app, api]
intensity: normal
prompt: |
  State the asset, trust boundary and invariant, then send the smallest request
  that would violate it. Keep a benign control.
mutations:
  - Swap the principal for a second account.
evidence:
  - Paired request and response plus the safe control.
stop_conditions:
  - Stop at the first reproducible proof.
safety:
  - Read-only requests only; no destructive write.
tags: [business-logic, authorization]
```

Keep IDs inside the documented ranges in [`catalog/README.md`](../catalog/README.md);
`CUSTOM-01` above only illustrates the field layout. Test expansion with a threat model:

```sh
uv run sak prompts expand CUSTOM-01 --threat-model runs/demo/threat-model.md
uv run sak prompts list --domain web --json
```

The expander is deterministic: it does not invent assets, and it marks a
hypothesis `inferred` when the threat model has none.

## Add an adapter

Only needed when `sak run` should execute the card. Read
[`adapters/README.md`](../adapters/README.md) first; it is the full interface.

Minimum checklist:

1. Add `adapters/<name>.py` exposing `ADAPTER_ID`, `NAME`, `REQUIRES`,
   `DESTINATION_POLICY`, `DESTINATION_REFUSAL`, `LICENSE_NOTICE`, `check()`,
   `build()`, `estimate_requests()`, `execute()` and `parse()`.
2. `check()` inspects the host only. No downloads, clones, installs or target
   traffic.
3. `build()` returns the command and display text; it must not execute.
4. `execute()` is only reachable through `sak run --execute` after the scope and
   budget gates.
5. `parse()` returns candidate records with `status: needs_validation`. An
   adapter never confirms a finding.
6. Declare `DESTINATION_POLICY`. `target` can be authorized by `scope.md`;
   `external` and `provider` are refused for execute because the real destination
   is chosen elsewhere.
7. No destructive, denial-of-service, brute-force or OAST defaults.
8. Set `adapter: <name>` in the tool card.
9. Add an offline test using `tests/fixtures/adapters/` data. No live target.

Dry-run smoke test:

```sh
uv run sak plan --suite web-blackbox --target http://127.0.0.1:8765 \
  --run-dir runs/adapter-check --allow-missing-requires
uv run sak run --run runs/adapter-check --step example-scanner --dry-run
```

The dry run must print a bounded command without contacting the target. Execution
requires a reviewed `scope.md`.

## Add an engine

Use an engine card under `engines/` when a heavy external platform should be
operable but not vendored. Required: `id`, `name`, `description`, `license`,
`requirements`, `commands` (`install`, `up`, `down`, `status`). Commands are dry
runs unless `--execute` is passed. Missing Docker, Compose, Node, Postgres or an
API key must produce a clean refusal, not a traceback. GPL/AGPL engines stay
external and gitignored; see [`docs/engines.md`](engines.md).

## Validation and tests

Before handing off any card change:

```sh
uv run sak catalog validate
uv run sak plan --suite <suite> --target <fixture> --json
uv run pytest -q
git status --short
```

Confirm no secret, no live target and no generated index was committed. If a
schema, card ID or CLI contract must change, stop and ask the owner first; those
are contracts shared by every task, adapter and report.
