# Sources, provenance and command map

This skill is original MIT-licensed text. It summarizes methods and names
capabilities; it does not copy upstream skill text. Where a capability belongs
to another component, the table below says where it lives and who owns it, so a
missing command is never invented.

## Provenance

| Component | Origin | License | How this skill uses it |
|---|---|---|---|
| `swiss-army-knife` skill | This repository (T4) | MIT | The operating contract, workflow, templates and routing in this folder |
| `security-audit` skill | Vendored upstream, pinned in `vendor/sources.lock.json` and `vendor/PROVENANCE.md` (T2) | MIT | Source-audit execution and the `confirmed` / `needs_validation` / `rejected` verdict model |
| `pwn-hunter` skill | Vendored upstream, pinned in `vendor/sources.lock.json` and `vendor/PROVENANCE.md` (T2) | MIT | Binary triage execution |
| Prompt cards `INV-*`, `VIBE-*`, `SSRF-*`, `LLM-*`, `MUT-01`, `VER-01`, `REP-01` | This repository's prompt library (T3), with upstream attributions recorded per card | MIT for original text; per-card `source` for anything adapted | Hunting, mutation, verification and reporting prompts |
| Tool cards, suites, engines and model profiles | This repository's catalog (T1, T2, T3, T5, T9, T10) | MIT for card text; tool licenses are per card | Selection, ranking and routing |
| Harness-engineering method | Graham Helton and Ryan Basden, *Harness Engineering* workshop book: <https://grahamhelton.github.io/harness-engineering-workshop-book/print.html> | Upstream | Evidence discipline, waves, oracles, improvement loop; summarized in `knowledge/methodology/` (T7) |
| CI pentest harness pattern | Team Zenn, "OpenCode Docker Actions AI pentest": <https://zenn.dev/team_zenn/articles/opencode-docker-actions-ai-pentest> | Upstream | The reason instructions alone are not a boundary; summarized in `knowledge/methodology/` (T7) |

The catalog is the source of truth for individual tools and prompts. When this
skill and a card disagree, the card and `sak catalog show <id>` win.

## Command map

`sak` is the CLI. The frozen command contract is `sak catalog`, `sak plan`,
`sak run`, `sak prompts`, `sak findings`, `sak report`, `sak doctor`,
`sak engine` and `sak eval`, each with `--json` where practical. Check
`sak --help` before relying on a subcommand: a partial install may not have every
module yet.

| Command | Purpose | Status in the v1 tree | Owner if missing |
|---|---|---|---|
| `sak catalog list\|show\|search\|validate\|export` | Inspect and validate cards | Available | `src/sak/catalog.py` (T1) |
| `sak plan --suite ... --target ... [--run-dir] [--json]` | Rank cards into role waves and write `plan.json` | Available | `src/sak/plan.py` (T1) |
| `sak doctor [--json]` | Report installed/missing tools and install hints | Available | `src/sak/doctor.py` (T1) |
| `sak engine list\|doctor\|install\|up\|down\|status` | Inspect and operate optional engines; dry-run by default | Available | `src/sak/engine.py` (T1), engine cards (T9) |
| `sak run --run RUN_DIR --step STEP_ID [--dry-run\|--execute]` | Run one adapter step with scope and budget enforcement | Contract command; adapters module | `src/sak/run.py` and `adapters/` (T5) |
| `sak prompts list\|show\|expand` | List, render and expand prompt cards | Contract command; prompts module | `src/sak/prompts.py` (T3) |
| `sak findings add\|list\|validate\|dedupe\|status` | Record, validate and dedupe findings | Contract command; findings module | `src/sak/findings.py` (T6) |
| `sak report RUN_DIR` | Render the three report artifacts | Contract command; report module | `src/sak/report.py` (T6) |
| `sak eval` | Run the fixture evaluation | Contract command; integration | `src/sak/eval.py` and `eval/` (T10) |
| `install.sh --dry-run` | Link this skill into an agent skill directory | Contract command; installer | `install.sh` (T10) |

Fallback rule: if a command is not in `sak --help`, use the manual procedure in
[selection.md](selection.md#manual-fallback) and record that the CLI path was
unavailable. Do not fabricate `plan.json`, findings or report output.

## Licenses

- **This repository and this skill:** MIT. See `LICENSE`.
- **Vendored skills:** MIT only, with upstream notice and a pinned source. See
  `THIRD_PARTY_NOTICES.md` and `vendor/PROVENANCE.md`.
- **Blackbird:** external checkout, GPL-3.0 with a CC BY-NC-SA component. It is
  **not vendored**; it is used through its own checkout and the adapter. The
  non-commercial clause is a usage limit you must check against your engagement.
- **T3MP3ST, PentAGI, ARTEX, AppleResearch:** external and optional, kept under
  the gitignored `vendor/external/` or the engine registry. Do not vendor them,
  do not bundle them, and check the upstream license before any use beyond
  local evaluation.
- **Nuclei, Semgrep, Gitleaks, Trivy, ffuf, sqlmap, ZAP, Playwright, Webseek:**
  each card records its own license and source. A permissive tool license is not
  authorization for a target.

Rule of thumb: MIT or equivalent may be vendored with provenance; GPL, AGPL and
unlicensed code stay external and gitignored. When the license is unclear, stop
and ask before using it.

## Attribution

- Verdict model (`confirmed`, `needs_validation`, `rejected`): adapted from the
  vendored `security-audit` skill; see `vendor/PROVENANCE.md` for the upstream
  project and pinned revision.
- Harness-engineering vocabulary (bounded hypotheses, evidence contract, waves,
  oracles, improvement loop): Graham Helton and Ryan Basden, summarized in
  `knowledge/methodology/harness-engineering.md`. This skill's text is an
  original operational summary, not a copy.
- CI harness caution (instructions are not a security boundary): Team Zenn,
  summarized in `knowledge/methodology/ci-pentest-harness.md`.
- Prompt-card identifiers follow the repository contract: `INV-01`…`INV-13`,
  `VIBE-01`…`VIBE-14`, `SSRF-01`…`SSRF-08`, `LLM-01`…`LLM-08`, `MUT-01`,
  `VER-01`, `REP-01`.

If an upstream notice is missing or a license is ambiguous, treat that as a
blocker: write the question, keep the component external, and continue with the
rest of the run.
