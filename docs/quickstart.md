# Quickstart

A clean checkout to a rendered report in about five minutes. Everything below is
offline and loopback-only. The demo target is the repository's own vulnerable
fixture, which is an authorized test target.

For the agent-skill path, read [skill-usage.md](skill-usage.md),
[harness-integration.md](harness-integration.md) and the optional
[Kali MCP guide](kali-mcp.md). The CLI quickstart below needs no model or MCP
server.

## 1. Prerequisites

- `git`
- `uv` (it installs and pins Python 3.12)
- `python3` for the fixture and the stdlib-only eval launcher (the project targets 3.12)

Optional: Node/npm for the vendor validators and some adapters; Docker only for
optional engines. `sak doctor` reports each missing tool with an install hint.
Nothing in this quickstart installs a global tool.

## 2. Sync the environment

```sh
uv sync
```

This installs Python 3.12, `PyYAML`, `jsonschema` and the pytest dev group into
`.venv/`, and installs the local `sak` console script in editable mode.

## 3. Check the host

```sh
uv run sak doctor
```

Expected shape: required tools (`python3.12`, `uv`, `git`) installed. Optional
tools may be missing; for example:

```text
TOOL       STATUS   VERSION   PATH   INSTALL HINT
---------- -------- --------- ------ -------------------------------------------
Nuclei     missing  -         -      go install ... nuclei@latest
...
3/13 tools installed; python 3.12.x
```

`doctor` exits `0` even when optional tools are missing. A missing required tool
is a setup problem, not a scan result.

## 4. Validate and inspect the catalog

```sh
uv run sak catalog validate
uv run sak catalog list
uv run sak catalog search idor
```

`catalog validate` is the gate: it checks every card against its schema, rejects
duplicate IDs and resolves suite references to tools and prompts. Expected:

```text
OK: 73 cards (model=5, prompt=47, suite=5, tool=16) in catalog
```

The exact count grows as cards are added; the important part is `OK` and exit
code `0`.

## 5. Plan a portfolio

```sh
uv run sak plan --suite web-blackbox --target http://127.0.0.1:8765 --json
```

The JSON plan contains `candidates`, `roles`, `waves` and `excluded`. Each
candidate carries its score and the five ranking components. On a host without
Nuclei, ZAP or a browser, strict planning may return an empty candidate list; the
`excluded` array then explains the missing requirement. To see the intended
portfolio anyway:

```sh
uv run sak plan --suite web-blackbox --target http://127.0.0.1:8765 \
  --allow-missing-requires
```

`--allow-missing-requires` only relaxes the host check. Scope, status, domain and
mode filters still apply. It never makes an uninstalled tool run.

Write the plan into a run directory:

```sh
uv run sak plan --suite web-blackbox --target http://127.0.0.1:8765 \
  --run-dir runs/my-run --allow-missing-requires
```

`runs/my-run/plan.json` now contains the same document. A run directory is the
unit of evidence: `scope.md`, `plan.json`, `findings.json`,
`coverage-ledger.json`, `evidence/` and the rendered reports live together.

## 6. Check the fixture

The fixture is a deliberately vulnerable standard-library app bound to loopback.
It is seeded with 14 issues and a set of safe endpoints that must stay clean.

```sh
python3 tests/fixtures/vuln_app/run.py --check
python3 tests/fixtures/vuln_app/run.py --reset
```

`--check` initializes and verifies the deterministic seed (three accounts, 14
issues) and exits `0`. `--reset` restores it.

To serve it manually on the documented port:

```sh
python3 tests/fixtures/vuln_app/run.py --port 8765
```

Then open <http://127.0.0.1:8765/>. Stop with Ctrl-C. The fixture refuses any
non-loopback bind host before it listens.

## 7. Run the demo

```sh
sh scripts/demo.sh
```

This single command:

1. writes `runs/demo/scope.md` and `runs/demo/threat-model.md`;
2. runs `sak plan --suite web-blackbox` into `runs/demo/plan.json`;
3. exports the web prompt library to `runs/demo/prompts.json` and expands the 14
   `VIBE-*` cards into `runs/demo/prompts/`;
4. starts the fixture on a loopback port and runs 14 positive probes plus 14
   negative controls, writing evidence, `findings.json`, `coverage-ledger.json`
   and `run-metadata.json`;
5. renders `REPORT.md`, `FINDINGS-DETAIL.md` and `NEEDS-VALIDATION.md`.

Expected tail:

```text
recall: 14/14 (100%)
precision: 100% (false positives: 0, control errors: 0, probe errors: 0)
coverage: 28/28 probes
time: 1.5s; cost: $0.00
duplicates: 0
threshold: PASS (min detected 10, false positives 0, control errors 0, probe errors 0)
...
report: demo-web-blackbox
findings=14 confirmed=14 needs_validation=0 rejected=0 excluded_confirmed=0
coverage=28/28 unverified=0 gaps=0
```

The demo picks its fixture port before writing scope, plan or metadata. It uses
`127.0.0.1:8765` when free and an ephemeral loopback port when that port is
busy, then passes the same port to the evaluation. Every artifact therefore
names one target; a busy port never produces a run under another target's scope.
Each issue has two coverage boundaries, one for the positive probe and one for
its safe control, so an errored probe appears as an uncovered gap instead of a
covered boundary.

The demo run directory is generated, not committed (`.gitignore` keeps only
`runs/.gitkeep`). Run `sh scripts/demo.sh` before `sak report runs/demo` on a
fresh clone.

## 8. Render the report

```sh
uv run sak report runs/demo
```

Read:

- `runs/demo/REPORT.md` — run, summary, confirmed findings, coverage gaps,
  evidence index and artifact list;
- `runs/demo/FINDINGS-DETAIL.md` — every record with its fingerprint, source,
  evidence hashes and status history;
- `runs/demo/NEEDS-VALIDATION.md` — open leads and confirmed claims blocked by
  missing or changed evidence.

A `confirmed` finding counts only when its evidence file is present and its
SHA-256 matches. Delete an evidence file and rerun the report: the claim moves
to "confirmed claims excluded from counts" instead of silently disappearing.

## 9. Run the metrics evaluation

```sh
python3 eval/run_fixture.py                       # metrics only, runs/eval
uv run sak eval --artifacts --run-dir runs/eval   # metrics + report artifacts
uv run sak report runs/eval
```

`python3 eval/run_fixture.py` writes `EVAL.json` and `EVAL.md`. Add
`--artifacts` (or use the CLI form) to also write the findings, ledger and
metadata needed by `sak report`. Useful options:

```sh
uv run sak eval --only VIBE-10          # one issue, fast smoke test
uv run sak eval --min-detected 14       # stricter gate
uv run sak eval --agent-command 'my-agent --target {target} --json'
```

The agent command is optional and skipped by default. It is the hook for an agent
evaluation against the installed meta-skill: point the command at `{target}`,
have the agent write ordinary findings, and print a JSON list of detected issue
IDs (for example `["VIBE-01"]`). The command runs while the fixture is still
alive, after a deterministic reset, and the fixture is terminated whether the
agent succeeds, fails or times out. It is split with `shlex` and executed without
a shell, so `{run_dir}` may contain spaces, quotes or semicolons. Command text,
stderr and error observations are masked before they reach `EVAL.json`,
`EVAL.md`, evidence or `--json` output. Agent cost and network use are not
measured and are separate from the `$0.00` deterministic fixture.

## 10. Install the agent skills

```sh
sh install.sh --dry-run
sh install.sh --local
```

Then start a new agent session so discovery sees
`.opencode/skills/swiss-army-knife/`. For a user-wide install:

```sh
sh install.sh --global
```

The installer links only MIT material and refuses anything else. See
[`docs/safety.md`](safety.md) and [`vendor/PROVENANCE.md`](../vendor/PROVENANCE.md).

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `error: uv is not installed` | Install uv, then rerun `sh install.sh` |
| `invalid catalog: ... issue(s)` | Read each line; `sak catalog validate` prints the file, card ID and JSON path |
| Plan shows every card excluded | A host tool is missing; read the reason or pass `--allow-missing-requires` |
| `preferred port ... is busy` | An explicit `--port` was occupied; stop that listener or omit `--port` to let eval choose 8765 or a free loopback port |
| `fixture did not become ready` | Check `runs/<run>/logs/fixture.log`; another process may hold the database |
| Report says `findings.json is missing` | Run the demo or `sak eval --artifacts` first; `sak report` never invents findings |
| `confirmed claims excluded` | The evidence file moved or changed; restore it or downgrade the finding |
| `sak prompts expand` fails | The threat-model path must exist; the demo writes `runs/demo/threat-model.md` |

## Next

- [Architecture](architecture.md) — modules, artifacts and determinism.
- [Safety](safety.md) — the authorization and evidence contract.
- [Adding tools](adding-tools.md) — cards, suites, prompts and adapters.
