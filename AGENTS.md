# Agent guide — swiss-army-knife-skills

Read this before changing the project with an AI coding agent.

## Product

`sak` is a portable, ranked security-tool and prompt suite for authorized web/API
and source-code assessments. It selects a portfolio for a target, runs skills, tools
and prompts in budgeted waves, records evidence, verifies findings and produces a
report.

## Start here

- [README.md](README.md) — install, commands, suites and safety.
- [docs/skill-usage.md](docs/skill-usage.md) — OpenCode skill invocation and workflow.
- [docs/harness-integration.md](docs/harness-integration.md) — harness and model setup.
- [docs/kali-mcp.md](docs/kali-mcp.md) — optional Kali MCP and the no-MCP path.
- [docs/benchmark.md](docs/benchmark.md) — dummy-target benchmark and caveats.
- [CONTRIBUTING.md](CONTRIBUTING.md) — tests, catalog rules and PRs.

## Commands

- `uv sync` installs Python 3.12, the runtime dependencies and the pytest group.
- `uv run sak <command>` uses the local console script; `uv run python -m sak` is equivalent.
- `uv run pytest -q` runs the offline suite.
- `uv run sak catalog validate` is the catalog gate.
- `uv run sak doctor` reports host tools and exact install hints.
- Adapters and engines are dry runs unless `--execute` is passed.

## Rules

- Authorized targets only. Active tools require a `scope.md` naming allowed hosts.
- Tests use the localhost fixture only. Do not test live external targets.
- No destructive or denial-of-service payloads by default.
- No secrets, tokens, cookies, keys, PII or real user data in code, docs, evidence
  or reports. `.env` is ignored; mask headers and values.
- Do not install global tools from a worker or CI. `sak doctor` prints the hint.
- Do not vendor GPL, AGPL or unlicensed code. Optional engines stay external.
- Catalog YAML is the source of truth; do not hand-edit generated indexes.
- Findings use `confirmed`, `needs_validation` or `rejected`.
- A hunter candidate is never `confirmed`.

## Skill and harness work

- The skill entry point is `skills/swiss-army-knife/SKILL.md`.
- Keep it harness-neutral and provider-neutral.
- `sak` is deterministic; only `sak hunt` starts a model-driven child.
- The install target is `./.opencode/skills` (`--local`) or `~/.agents/skills`
  (`--global`).
- MCP is optional. Any change must still work with a plain shell.

## Docs and benchmark

- New public docs need a link from `README.md` or an existing index.
- New benchmark records go in `benchmarks/` with no secrets and a matching test.
- The benchmark denominator is the profile's `expected` rubric, not "all possible
  vulnerabilities".
- Update `CHANGELOG.md` for user-visible changes.

## Style

- Python 3.12, standard library first; PyYAML and jsonschema are the only runtime
  dependencies.
- Match the surrounding naming, error handling and evidence structure.
- One concern per commit. Keep tests offline.
- No `print` debugging in library code; use the CLI output contract.
