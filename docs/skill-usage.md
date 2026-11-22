# Using the swiss-army-knife skill in OpenCode

This project ships three MIT agent skills under `.opencode/skills/` after a local
install:

| Skill | Use |
|---|---|
| `swiss-army-knife` | Authorized assessment orchestration, catalog selection, evidence and reporting |
| `security-audit` | Codebase/API security review and vulnerability classes |
| `pwn-hunter` | Binary exploitation and memory-corruption work |

The `swiss-army-knife` skill is the operating layer for the `sak` CLI. It decides
what to run, in what order, with which evidence, and what may be claimed afterwards.
The CLI and the catalog remain the source of truth.

## 1. Install for this project

```sh
sh install.sh --dry-run    # plan only; no writes and no uv sync
sh install.sh --local      # ./.opencode/skills/{swiss-army-knife,security-audit,pwn-hunter}
sh install.sh --global     # ~/.agents/skills/{swiss-army-knife,security-audit,pwn-hunter}
```

`--local` is the project install and is the right choice for this repository.
`--global` links the same skills into `~/.agents/skills/` for every project. The
installer runs `uv sync`, links only MIT skills, refuses a GPL/AGPL/unlicensed
directory, and never prints environment values.

Verify the links:

```sh
ls -la .opencode/skills
for d in .opencode/skills/*; do test -f "$d/SKILL.md" && echo "OK $d"; done
```

`.opencode/` is gitignored. The install is a symlink to the checked-out skill, so
editing `skills/swiss-army-knife/SKILL.md` updates the installed skill immediately.

## 2. Load the skill in OpenCode

The skill is exposed to OpenCode as id `swiss-army-knife`. If the current session
was started before the install, reload the session or restart OpenCode so the skill
catalog picks up the new links. Then either invoke it directly or ask for it by name:

```text
Use the swiss-army-knife skill to plan a web-blackbox assessment of
http://127.0.0.1:8080. Do not execute active steps until I approve the scope.
```

```text
Use the swiss-army-knife skill to run the vuln-bank profile, verify the rubric,
and render the report. Keep evidence under runs/ and mask all secrets.
```

The skill is also a normal Markdown entry point; a human or another harness can read
`skills/swiss-army-knife/SKILL.md` and its `references/` files directly.

## 3. Operating contract

The skill's rules are deliberately strict:

1. **No scope, no action.** Create `runs/<run-id>/scope.md` before the first
   request. It names allowed hosts, paths, methods, accounts and the window. If it
   is missing or ambiguous, stop and ask.
2. **Dry-run first.** Adapters and engines print their command unless `--execute`
   is passed. A read-only target request is still active execution and needs the
   scope gate.
3. **Verified cards only, automatically.** The planner selects `status: verified`
   cards. Unverified or experimental cards are manual, dry-run and explicitly
   approved.
4. **Hunters produce candidates.** A hunter never writes `confirmed`; the verifier
   tries to disprove the claim from fresh evidence.
5. **Evidence or it did not happen.** `confirmed` needs reproducible, redacted
   request/response evidence. Otherwise the verdict is `needs_validation` or
   `rejected`.
6. **Never print or store secrets.** Tokens, cookies, passwords, keys, card data
   and environment values are masked in evidence and reports.

## 4. Workflow and commands

Run from the repository root.

```sh
uv sync
uv run sak doctor
uv run sak catalog validate

# Scope and plan
mkdir -p runs/my-assessment
$EDITOR runs/my-assessment/scope.md
uv run sak plan --suite web-blackbox \
  --target http://127.0.0.1:8080 \
  --run-dir runs/my-assessment

# Hunt bounded hypotheses (optional; requires the model key)
NEAR_AI_API_KEY="$NEAR_AI_API_KEY" \
uv run sak hunt \
  --run runs/my-assessment \
  --target http://127.0.0.1:8080 \
  --prompts INV-01 --max-agents 1 --timeout 180 --json

# Prove the profile checks
uv run sak exploit \
  --run runs/my-assessment \
  --target http://127.0.0.1:8080 \
  --profile targets/dvwa/blackbox/profile.yaml --json

# Score the rubric and render the report
uv run sak verify --run runs/my-assessment \
  --profile targets/dvwa/blackbox/profile.yaml --json
uv run sak report runs/my-assessment
```

The order matters: `sak exploit` produces the proof artifacts, `sak verify` maps
them to the rubric and writes `verify.json`/`VERIFICATION.md`, and `sak report`
renders the findings and coverage set. `sak hunt` is optional signal and never
counts as a confirmed finding.

For the Mac-to-remote-lab path, use `127.0.0.1:15000` for vuln-bank and
`127.0.0.1:8080` for DVWA. Replace `sak-lab` below with your SSH alias:

```sh
ssh -N -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
  -L 15000:127.0.0.1:5000 sak-lab
```

Mac port `5000` is commonly AirTunes; never use it for vuln-bank. The full command
matrix is in [blackbox-pilot.md](blackbox-pilot.md).

## 5. Evidence layout

| File | Meaning |
|---|---|
| `scope.md` | Authorization and budget |
| `exploit/*.json` | One sanitized proof artifact per check |
| `hunt/*.json` | Candidate records; always `needs_validation` |
| `verify.json`, `VERIFICATION.md` | Rubric table and coverage statement |
| `findings.json` | Confirmed findings and evidence hashes |
| `coverage-ledger.json` | Boundary-to-probe coverage |
| `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md` | Rendered report set |
| `run-metadata.json` | Target, scope, revision and operator labels |

Keep `runs/` until the report is accepted. The evidence is the deliverable, not the
console output.

## 6. Using the dummy targets as a benchmark

The accepted DVWA Low and vuln-bank runs are the first skill benchmark:

| Target | Rubric | Confirmed | Coverage |
|---|---|---|---|
| vuln-bank | 15 | 15 | 15/15 |
| DVWA Low | 11 | 11 | 11/11 |

The benchmark definition, metrics, caveats and per-issue records are in
[docs/benchmark.md](benchmark.md) and `benchmarks/*.json`. Use it to compare a changed
skill or engine against a fixed rubric, not to claim that every possible
vulnerability was found.

## 7. Troubleshooting

| Symptom | Check |
|---|---|
| Skill not listed in OpenCode | Reload/restart the session; confirm `.opencode/skills/swiss-army-knife/SKILL.md` resolves |
| `uv: command not found` | Install `uv`; `sh install.sh --local` needs it |
| Installer refuses a skill | Only MIT-licensed skill directories are linked; check the license |
| `sak exploit` refuses the target | The target host/port is not in the profile's `scope.allowed_hosts` |
| Login or CSRF failure | Re-read the profile contract; DVWA forms use per-form tokens and some Low forms have none |
| `sak report` renders zero findings | `findings.json` and `coverage-ledger.json` are missing; `sak verify` writes the verification, not the findings document |
| Tunnel drops mid-run | Use a keepalive supervisor; a one-shot `ssh -f -N` can be closed on idle |

## 8. Safety

Authorized loopback labs only by default. Active tools require a written scope.
No destructive or denial-of-service payloads. No real credentials, customer data or
third-party targets. The agent drafts; the human owns the disclosure.
