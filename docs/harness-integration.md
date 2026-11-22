# Harness and model integration

`sak` has two layers:

- the **skill** — plain Markdown instructions in `skills/swiss-army-knife/SKILL.md`;
- the **CLI** — deterministic commands for planning, checks, verification and reports.

A harness supplies the shell, file access and model. The skill decides what to run,
in what order, and what may be claimed. The CLI supplies the evidence contract.
Neither layer requires a specific vendor.

## 1. Choose an integration shape

| Shape | Use when | Install |
|---|---|---|
| Skill only | The agent already has a shell and can run `uv` | Link `skills/swiss-army-knife` into the harness skill directory |
| Skill + CLI | You want plan, checks, verify and report | `sh install.sh --local` or `--global` |
| Skill + CLI + Kali MCP | The harness executes tools through a Kali MCP server | Link the skill and configure the MCP server |
| CLI only | A human or CI runs the suite | `uv sync` and `uv run sak ...` |

## 2. OpenCode

```sh
sh install.sh --local
```

This links `.opencode/skills/swiss-army-knife`, `.opencode/skills/security-audit`
and `.opencode/skills/pwn-hunter` in the project. Reload the OpenCode session if it
was started before the install. Invoke the skill by name or with a normal request:

```text
Use the swiss-army-knife skill to plan a web-blackbox assessment of
http://127.0.0.1:8765. Create the scope, choose the cards, and stop before active
execution.
```

The full OpenCode command and evidence workflow is in
[skill-usage.md](skill-usage.md).

## 3. Claude Code, Codex and custom agents

The skill is a normal `SKILL.md` with YAML frontmatter. Point the harness's skill
directory at `skills/swiss-army-knife`, or use the global links:

```sh
sh install.sh --global          # ~/.agents/skills/{swiss-army-knife,security-audit,pwn-hunter}
```

If your harness expects another skill directory, symlink the same source rather
than copying it, so updates stay in one place:

```sh
mkdir -p ~/.config/<harness>/skills
ln -sfn "$PWD/skills/swiss-army-knife" ~/.config/<harness>/skills/swiss-army-knife
```

For a Codex-style harness, keep `AGENTS.md` at the repository root and start the
agent there. For a custom harness, give the model the skill text and the CLI
commands; no plugin API is required.

## 4. Models

`sak plan`, `sak exploit`, `sak verify` and `sak report` do **not** call a model.
Only `sak hunt` starts a child agent.

### OpenCode + Near AI (default)

```sh
export NEAR_AI_API_KEY="..."       # never commit it
uv run sak hunt \
  --run runs/my-hunt \
  --target http://127.0.0.1:8080 \
  --prompts INV-01 \
  --model nearai/deepseek-ai/DeepSeek-V4.1-Flash-1017-abliterated \
  --max-agents 1 --timeout 180 --json
```

The default runner is:

```text
opencode run --standalone --format json --model <model>
```

The rendered hunter prompt is appended as the final argument. The child must emit
candidate JSON in its final agent message (or plain candidate JSON stdout). The
runner parses the JSONL `text` parts and records candidates as
`needs_validation`, never `confirmed`.

### Another OpenCode provider

Configure the provider in OpenCode, then pass its model id:

```sh
uv run sak hunt ... --model provider/model-id
```

The model id is whatever your OpenCode configuration exposes; `sak` does not keep
a provider registry or an API key.

### A custom agent runner

Use `--runner` when the child is not OpenCode. The command is split with
`shlex`; the prompt is always appended as the last argument:

```sh
uv run sak hunt \
  --run runs/my-hunt --target http://127.0.0.1:8080 --prompts INV-01 \
  --runner "my-agent run --json" --json
```

The runner contract is narrow:

- stdout must be candidate JSON, or JSONL whose final text part contains it;
- the candidate object may use `candidates`, `findings` or `results`;
- the child reports observations, not `confirmed` verdicts;
- stderr is captured and masked;
- a timeout kills the child process group.

### Model roles

Use the role cards in [models.md](models.md) and `catalog/models.yaml`:

| Role | Typical choice | Why |
|---|---|---|
| hunting | cheap, fast, large context | reads surface and proposes probes |
| generation | low-refusal, format-disciplined | payload and sequence variants |
| verification | high-effort reasoning | adjudicates evidence and controls |
| reporting | structured writer | keeps report fidelity |

Run the refusal probe in `knowledge/models/refusal-probe.md` before a generation
wave. A refusal on a permitted step is data, not a reason to disguise the request.

## 5. Prerequisites by harness

| Capability | Needed for | If missing |
|---|---|---|
| shell | every `sak` command | the skill can only advise, not execute |
| file read/write | scope, profiles, evidence | mount the repo read-write |
| `uv` + Python 3.12 | CLI | `uv sync` will fail; install `uv` |
| `curl` | readiness checks | use the harness HTTP tool |
| Docker | local labs/engines | use a remote lab or skip engines |
| Node/Playwright | browser evidence | mark browser checks `needs_validation` |
| Kali MCP | executing tools inside Kali | use the local shell/Kali WSL/SSH path |

## 6. Scope and evidence in any harness

1. Create `runs/<run-id>/scope.md` before the first request.
2. Keep the working directory at the repository root so `--run` paths and profiles
   resolve consistently.
3. Pass secrets through the environment, never through the prompt or a command line
   that will be logged.
4. Keep artifacts under `runs/`; do not let a child write into the repo root.
5. Run `sak verify` after `sak exploit`; a candidate is not a finding.
6. Run `sak report` only after `findings.json` and `coverage-ledger.json` exist.

## 7. Kali MCP, or no MCP

The skill works in both modes. MCP changes **where** a command runs, not the
commands or the evidence contract. See [kali-mcp.md](kali-mcp.md) for the setup
checklist, minimum tool surface and safety rules.

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| Skill not visible | Reload the harness; confirm the symlink resolves to `skills/swiss-army-knife/SKILL.md` |
| Model id rejected | Use the exact id the harness lists; `sak` does not translate ids |
| `NEAR_AI_API_KEY` missing | Set it for the default Near AI runner, or use `--runner`/`--model` |
| Child exits with empty stdout | The runner must emit candidate JSON; check the harness JSON mode |
| Child artifacts in repo root | Start `sak hunt` from `runs/<run>/scratch` or set the child cwd |
| MCP command runs in the wrong directory | Set the MCP workspace and `cwd` to the repo checkout |
| Evidence missing after a run | Check `runs/<run>/exploit/` and the scope path; `sak verify` reports gaps |
