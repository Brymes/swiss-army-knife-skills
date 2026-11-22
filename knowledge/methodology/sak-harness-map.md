# SAK harness map

This maps the harness-engineering book to SAK v1. The book's components come from
[harness-engineering.md](harness-engineering.md). "Designed" means the path or command is a
frozen pack contract (`CONTEXT.md` C2/C6) owned by another task and not yet necessarily
merged; "partial" means v1 covers the useful part but not the book's full mechanism;
"deferred" means it is not built in v1. At the time of writing, T1–T10 are in flight, so
no cell should be read as a claim that the code already exists.

## Summary

| Component | SAK v1 | Status |
|---|---|---|
| Claim/evidence discipline | Finding schema, verdicts, evidence requirement, verifier prompt, report artifacts, evidence standard in `docs/improvement-loop.md` | Designed |
| Local validation environment | Local vulnerable fixture, `scope.md` gate, `sak doctor`, dry-run adapter checks | Designed |
| External integrations / MCP | Three adapters plus catalog `mcp` kind and Webseek MCP example; no generic MCP client | Partial |
| Operational interfaces | `sak` CLI commands, run-directory view, meta-skill references | Designed |
| Memory / research state | Run directory with state, coverage ledger, findings and evidence; no thread index or hypothesis store | Partial |
| Context management | Prompt IDs, skill references, plan waves and budgets, `--json`; no compaction policy | Partial |
| Telemetry | Per-run logs and run metadata; no append-only event ledger or OpenTelemetry | Partial |
| Skills | `swiss-army-knife` meta-skill, vendored MIT skills, install links | Designed |
| Deterministic tools | Nuclei, Blackbird and Webseek adapters with parsers and dry-run; Semgrep/Gitleaks/Trivy are cards only | Partial |
| Hooks | No agent-lifecycle hooks; `sak run` performs preflight scope/budget enforcement | Deferred |
| Oracles | `sak doctor` (tool state), Webseek search, model cards; no target-specific data oracle | Partial |
| Reporting / disclosure | Report generator, three verdicts, REP-01 prompt, human-owned send | Designed |
| Routing | — | Deferred (book also lists it as coming soon) |
| Advanced research state | — | Deferred (book also lists it as coming soon) |

## Component detail

### Claim / evidence discipline

- **Book requirement:** separate observation, interpretation and hypothesis; each claim
  needs evidence under stated conditions; a stopped validation keeps its blocker and next
  action.
- **SAK v1:** `schemas/finding.schema.json` and `src/sak/findings.py` (T6) carry the three
  verdicts `confirmed`, `needs_validation` and `rejected`, and reject `confirmed` records
  without evidence. `catalog/prompts/` (T3) includes the `VER-01` verifier and `REP-01`
  reporting prompts. `src/sak/report.py` (T6) renders `REPORT.md`,
  `FINDINGS-DETAIL.md` and `NEEDS-VALIDATION.md`. The standard itself lives in
  `docs/improvement-loop.md` under "Evidence standard".
- **Gap:** the schema can require an evidence pointer, but it cannot judge whether the
  evidence supports the claim. That remains a human review step.
- **Owner:** T6 (schemas, findings, report), T3 (prompts), T7 (standard).

### Local validation environment

- **Book requirement:** a known target, a small working toolset, an observable normal
  operation and retained setup evidence.
- **SAK v1:** `tests/fixtures/vuln_app/` (T8) is the authorized localhost fixture with 14
  seeded issues and a reset path. `runs/<run-id>/scope.md` names allowed hosts; active
  adapters refuse without a scope entry (T5). `sak doctor` (T1) reports installed and
  missing tools with install hints. `tests/fixtures/catalog/` and `tests/fixtures/adapters/`
  give offline readiness checks.
- **Gap:** there is no single `sak lab up` command in v1; the fixture is started by its own
  test/demo entry point. Readiness evidence is a run artifact, not a dedicated record.
- **Owner:** T8 (fixture), T1 (doctor), T5 (scope enforcement), T10 (demo).

### External integrations / MCP

- **Book requirement:** use an external source only for a question local files cannot
  answer; bound requests, keep provenance, treat responses as data.
- **SAK v1:** `adapters/` (T5) wraps Nuclei, Blackbird and Webseek. The catalog schema (T1)
  has an `mcp` kind, and the Webseek card documents an MCP configuration example. `--dry-run`
  is the default; `--execute` is explicit.
- **Gap:** SAK has no generic MCP client, server registry or credential broker. `webseek`
  is the only integration intended for research-style external lookup, and it is optional.
- **Owner:** T5; a general MCP client is deferred beyond v1.

### Operational interfaces

- **Book requirement:** named commands for repeated actions and views over existing work.
- **SAK v1:** the `sak` CLI with `sak catalog`, `sak plan`, `sak run`, `sak prompts`,
  `sak findings`, `sak report`, `sak doctor`, `sak engine` and `sak eval` (C2). The run
  directory is the shared view:
  `plan.json`, `state.json`, `coverage-ledger.json`, `findings.json`, `evidence/`, `logs/`
  and the report artifacts (C6). `skills/swiss-army-knife/references/` (T4) explains the
  same commands to a non-CLI agent.
- **Gap:** no web view; no `sak status` command. Views are files plus CLI output, which is
  enough for humans and agents to read the same data.
- **Owner:** T1, T5, T6, T10.

### Memory / research state

- **Book requirement:** preserve a hypothesis, its status, evidence, assumptions,
  environmental conditions, rejected paths, open questions and one next action; make it
  discoverable and retrievable across sessions.
- **SAK v1:** `runs/<run-id>/state.json` records the current run, `coverage-ledger.json`
  records what was and was not tested, `findings.json` holds verdicts and evidence links,
  and `NEEDS-VALIDATION.md` carries open questions. The artifact names are fixed so a later
  session can find them.
- **Gap:** no `threads/<id>/index.md` equivalent, no per-hypothesis directory and no reopen
  condition. A new session must read the run directory rather than an index. This is the
  largest book-to-SAK gap.
- **Owner:** T6 for the ledger/findings; a thread-style research store is deferred.

### Context management

- **Book requirement:** select current, relevant and authoritative information; filter
  bulky tool output before it reaches the model.
- **SAK v1:** prompt cards have stable IDs (`INV-*`, `VIBE-*`, `SSRF-*`, `LLM-*`, `MUT-01`,
  `VER-01`, `REP-01`) so a run selects one hunter instead of loading the library. Plans
  assign waves and budgets. Adapters parse tool output into finding records rather than
  dumping raw output. `--json` gives a compact machine view.
- **Gap:** no measured token budget, no automatic summarizer and no pre-compaction hook.
  The meta-skill tells the agent what to read; it does not enforce a context policy.
- **Owner:** T3, T4, T5; compaction is deferred.

### Telemetry

- **Book requirement:** deterministic event capture at the point of action, outside the
  agent's account; high-volume data stays out of context.
- **SAK v1:** each run writes `logs/` and run metadata validated by
  `schemas/run-metadata.schema.json` (T6). The T10 eval records recall, precision,
  coverage, time, cost and duplicate metrics.
- **Gap:** no append-only JSONL event stream, session/turn IDs or hook-produced events.
  Cost is recorded only when the caller supplies it. No telemetry backend or retention
  policy.
- **Owner:** T6 (metadata), T10 (eval metrics); event telemetry is deferred.

### Skills

- **Book requirement:** a reusable `SKILL.md` folder with a precise description, optional
  references/assets, and tools that actually perform the actions.
- **SAK v1:** `skills/swiss-army-knife/` (T4) with `SKILL.md` and references for workflow,
  selection, safety, prompt mutation, reporting and sources. `vendor/skills/pwn-hunter/`
  and `vendor/skills/security-audit/` (T2) are MIT, with provenance. `install.sh` (T10)
  links the skills into OpenCode or the global agent directory.
- **Gap:** skills improve consistency, not determinism. No per-skill permission manifest
  beyond `allowed-tools` in the spec.
- **Owner:** T2, T4, T10.

### Deterministic tools

- **Book requirement:** one defined, repeatable question; saved rule, revision, raw result,
  coverage and limits; compare matched expressions, not counts; test positive and negative
  cases.
- **SAK v1:** Nuclei, Blackbird and Webseek adapters (T5) each expose `check`, a dry-run
  command, an execute path and a parser. Parsers normalize output into finding candidates;
  tests use fake binaries and fixture output. `sak doctor` is the tool-availability check.
  Catalog `status: verified` gates auto-run.
- **Gap:** Semgrep, Gitleaks, Trivy, ffuf, sqlmap and ZAP exist as cards (T9) but have no
  adapters in v1. There is no coverage-completeness check equivalent to the book's
  expected-vs-scanned path comparison.
- **Owner:** T5 (adapters), T9 (cards); source-scan adapters are deferred.

### Hooks

- **Book requirement:** observe or block actions at lifecycle events, independent of model
  compliance.
- **SAK v1:** no agent-lifecycle hook system. The nearest controls are `sak run` preflight
  (scope allowlist and budgets), adapter `check`/dry-run, and `AGENTS.md` instructions.
  These are harness checks, not event hooks.
- **Gap:** no `PreToolUse` block, no `SessionStart` scope load, no `PreCompact` state save,
  no automatic approval classifier. The Zenn pattern in
  [ci-pentest-harness.md](ci-pentest-harness.md) shows why instructions alone are not a
  boundary.
- **Owner:** deferred beyond v1; any future hook must live in the harness, not in a prompt.

### Oracles

- **Book requirement:** expose data the model lacks so a question becomes a reproducible
  query; the oracle supplies data, not the security decision.
- **SAK v1:** `sak doctor` answers "what tools are present and functional"; Webseek answers
  bounded external search questions; `catalog/models.yaml` (T9) records model roles and
  refusal notes. These are small, general oracles.
- **Gap:** no target-specific oracle such as a dependency/advisory database, an RBAC or
  permission table, or a "which vendors use this API" index. The book's Helm/RBAC oracle is
  deferred.
- **Owner:** T9 for model cards; target oracles are deferred.

### Reporting / disclosure

- **Book requirement:** decide report, hold or refute; verify the current release and
  private route; separate facts, inferences and unknowns; agent drafts, human sends.
- **SAK v1:** `src/sak/report.py` (T6) renders `REPORT.md`, `FINDINGS-DETAIL.md` and
  `NEEDS-VALIDATION.md` with evidence links, a before/after table and secret masking.
  `REP-01` (T3) defines the reporting prompt. Findings keep `needs_validation` rather than
  being inflated to `confirmed`.
- **Gap:** SAK does not identify a maintainer, a private channel or a disclosure window,
  and it deliberately has no send or publish tool. The human supplies those facts.
- **Owner:** T6, T3; disclosure routing is human-owned by design.

### Routing and advanced research state

Both appear in the book as "coming soon". SAK v1 has plan ranking (`src/sak/plan.py`) but
no model-routing layer and no advanced hypothesis graph. Deferred.
