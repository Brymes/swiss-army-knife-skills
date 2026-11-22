# Swiss Army Knife Skills (`sak`)

[![CI](https://github.com/Brymes/swiss-army-knife-skills/actions/workflows/ci.yml/badge.svg)](https://github.com/Brymes/swiss-army-knife-skills/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`sak` is a portable, ranked security-tool and prompt suite for **authorized**
web/API and source-code assessments. It selects a small portfolio for a target,
runs skills, tools and prompts in budgeted waves, records evidence, verifies
findings and renders a report.

- **Catalog first.** Tool, prompt, suite, engine, model and source cards are YAML
  validated against JSON Schema. The catalog is the source of truth.
- **Ranked, not random.** Each card scores `2*impact + reliability + stealth -
  effort - noise`; the plan explains the score and the role.
- **Dry-run first.** Adapters and engines print their command unless `--execute`
  is passed, and active execution needs a `scope.md`.
- **Evidence or it did not happen.** A finding is `confirmed` only with evidence
  whose SHA-256 still matches. Unverified claims stay `needs_validation` or
  `rejected`.
- **Offline by default.** Tests and the demo use the localhost vulnerable fixture
  only. No live external target, Docker or paid API is required.

Start with the [quickstart](docs/quickstart.md).

## Requirements

- Python 3.12 (managed by `uv`)
- `uv`, `git`; Node/npm only for optional adapters and vendor validators
- Docker only for optional engines
- Missing host tools are reported by `uv run sak doctor` with install hints; the
  project never installs them for you.

## Install

```sh
git clone https://github.com/Brymes/swiss-army-knife-skills.git
cd swiss-army-knife-skills
uv sync
uv run sak doctor
```

Install the agent skills (a symlink install, MIT skills only):

```sh
sh install.sh --dry-run    # show uv sync and link plan; change nothing
sh install.sh --local      # ./.opencode/skills/{swiss-army-knife,pwn-hunter,security-audit}
sh install.sh --global     # ~/.agents/skills/{...}
```

The installer syncs the environment with `uv`, links the `swiss-army-knife`
meta-skill and links only vendored skills whose `LICENSE` is MIT. A GPL, AGPL,
unlicensed or non-MIT directory is refused, never copied. It never prints or
writes environment values or secrets. See [docs/safety.md](docs/safety.md).

For the OpenCode invocation, scope gate and evidence workflow, read
[docs/skill-usage.md](docs/skill-usage.md). The accepted dummy-target baseline is in
[docs/benchmark.md](docs/benchmark.md) and [`benchmarks/`](benchmarks/README.md).

## Use your own harness and model

The CLI is deterministic and does not call a model. The skill is plain Markdown, so
any harness that can read a skill, run a shell and pass a model can use it.

- [Harness integration](docs/harness-integration.md) — OpenCode, Claude Code, Codex,
  custom agents, model selection and the `--runner` contract.
- [Kali MCP, optional](docs/kali-mcp.md) — run the skill through a Kali MCP server,
  or use the local shell/Kali WSL/SSH path with no MCP.
- [Models](docs/models.md) — hunter, generator, verifier and reporter roles, key
  handling and provider-neutral selection.

The only model-driven command is `sak hunt`. `sak plan`, `sak exploit`, `sak verify`
and `sak report` work without a model or a paid API.

## Quickstart

```sh
uv sync
uv run sak doctor
uv run sak catalog validate
uv run sak catalog list
uv run sak plan --suite web-blackbox --target http://127.0.0.1:8765 --json
sh scripts/demo.sh
uv run sak report runs/demo
```

The demo is entirely loopback: it plans a `web-blackbox` engagement, expands the
web prompt library against a local threat model, runs 14 positive probes and 14
negative controls against `tests/fixtures/vuln_app`, and renders
`runs/demo/REPORT.md`. It must detect at least 10 of the 14 seeded issues and
record zero confirmed false positives; the bundled run detects all 14. The full
walkthrough is in [docs/quickstart.md](docs/quickstart.md).

## Commands

| Command | Purpose |
|---|---|
| `sak catalog list/show/search/validate/export` | Query and validate cards |
| `sak plan --suite SUITE --target TARGET` | Rank a portfolio and emit role waves |
| `sak doctor` | Report installed and missing host tools with hints |
| `sak prompts list/show/expand` | Filter the prompt library and expand hypotheses |
| `sak run --run RUN_DIR --step ID` | Dry-run or execute one planned adapter step |
| `sak findings validate/list/add/dedupe/status` | Manage verdicts and evidence |
| `sak report RUN_DIR` | Render `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md` |
| `sak eval` | Run the deterministic fixture evaluation and metrics |
| `sak engine list/doctor/install/up/down/status` | Optional external engines |

All commands accept `--json` where a machine-readable result is useful. The
engine and adapter actions are dry runs unless `--execute` is passed.

## Suites

| Suite | Profile | Focus | Role budget (P/S/F/B) |
|---|---|---|---|
| `web-blackbox` | `web-blackbox` | web/API scanning, authz and injection hunters | 3/4/3/1 |
| `web-source` | `web-source` | SAST, secrets, dependency review, source audit skill | 3/3/2/0 |
| `binary` | `binary` | lab binary triage through `pwn-hunter` | 1/1/0/0 |
| `osint` | `custom` | passive public footprint; experimental cards need approval | 1/2/1/0 |
| `llm` | `custom` | LLM prompt injection, retrieval, tool calls, quota | 2/3/2/0 |

Each suite documents its passive, broad, targeted, brute and verify waves,
parallelism rules, budgets and stop conditions in its `notes` field. The planner
emits one wave per selected role (`primary`, `support`, `fallback`, `brute`).
Role caps and filters live in the YAML card; see
[`catalog/README.md`](catalog/README.md).

Typical plan:

```sh
uv run sak plan --suite web-blackbox --target http://127.0.0.1:8765 \
  --run-dir runs/my-run --allow-missing-requires
```

`--allow-missing-requires` shows the intended portfolio when a host tool is
absent. Without it, cards whose `requires` are missing are listed as excluded,
with the reason.

## Skill benchmark

The installed skill is measured against two fixed loopback rubrics:

| Target | Rubric | Confirmed | Coverage |
|---|---|---|---|
| vuln-bank | 15 | 15 | 15/15 |
| DVWA Low | 11 | 11 | 11/11 |

This is profile-rubric coverage, not a claim that every possible vulnerability was
found. The method, caveats, per-issue records and reproduction commands are in
[docs/benchmark.md](docs/benchmark.md) and [`benchmarks/`](benchmarks/README.md).

## Demo and evaluation

```sh
sh scripts/demo.sh                 # full loopback demo in runs/demo
python3 eval/run_fixture.py        # metrics only in runs/eval
uv run sak eval --artifacts --run-dir runs/eval   # metrics plus report artifacts
uv run sak report runs/eval
```

The evaluation records recall (detected / 14), precision (true positives /
(true positives + false positives)), failed controls, control errors, probe
errors, executed probe coverage, wall time, deterministic cost (`$0.00`: local
fixture, no paid API) and duplicate fingerprints. A failed control, control
error or probe error fails the threshold even when every positive probe detects.
It writes `EVAL.json` and `EVAL.md`; `--artifacts` also writes the findings,
coverage ledger and run metadata needed by `sak report`. An optional
`--agent-command` runs an external agent while the fixture is live, after a
deterministic reset; its command/stderr are masked and its cost and network use
are recorded as unmeasured, separate from the `$0.00` deterministic run. No
command is run by default.

## Repository map

```text
catalog/          tools, prompts, suites and model cards (YAML, source of truth)
schemas/          JSON Schema for every card and run artifact
src/sak/          CLI: catalog, plan, doctor, prompts, run, findings, report, eval, engine
adapters/         nuclei, blackbird and webseek adapters (dry run by default)
engines/          optional external engine cards and wrappers
skills/           the MIT swiss-army-knife meta-skill
benchmarks/       durable secret-free summaries of the dummy-target benchmark
vendor/skills/    MIT vendored skills with pinned provenance
tests/            offline tests and the localhost vulnerable fixture
scripts/demo.sh   loopback demo orchestrator
eval/             stdlib-only evaluation launcher
docs/             quickstart, architecture, safety and extension guides
runs/             generated run directories (gitignored; .gitkeep only)
```

Architecture and data flow: [docs/architecture.md](docs/architecture.md).
Adding cards and adapters: [docs/adding-tools.md](docs/adding-tools.md).

## Safety

Authorized targets only. Active tools require a written `scope.md` naming the
allowed hosts, methods, accounts and window. The test suite and demo use the
localhost fixture on `127.0.0.1:8765`; live external targets, destructive
payloads, denial of service and real user data are out of scope. Evidence and
reports are masked; tokens, cookies, authorization headers and personal data are
never stored. Read the full contract in [docs/safety.md](docs/safety.md).

## Contributing and security

Contributions are welcome under the MIT license. Read
[CONTRIBUTING.md](CONTRIBUTING.md) for setup, tests, catalog changes and the skill
install. Report security issues in `sak` itself through a private GitHub security
advisory as described in [SECURITY.md](SECURITY.md). Maintainers publishing a
release should follow [docs/publishing.md](docs/publishing.md).

## License

Our code and the `swiss-army-knife` skill are MIT. Vendored skills are MIT with
their upstream licenses and pins in [`vendor/PROVENANCE.md`](vendor/PROVENANCE.md)
and [`vendor/sources.lock.json`](vendor/sources.lock.json). Required notices are
in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). GPL, AGPL and unlicensed
code is never vendored; optional engines stay external and gitignored.
