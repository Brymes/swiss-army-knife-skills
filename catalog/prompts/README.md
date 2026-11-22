# Prompt cards

One YAML document per category, each with a `prompts:` list. Every card is
validated against `schemas/prompt.schema.json` by `sak catalog validate` and is
loaded by `sak prompts list|show|expand`.

Card IDs are frozen by the pack contract:

| Prefix | Count | Purpose |
|---|---|---|
| `INV-01..13` | 13 | Invariant hunters for broken enforcement and state |
| `VIBE-01..14` | 14 | Vibe-coded application attack cards |
| `SSRF-01..08` | 8 | Server-side request forgery techniques and evidence |
| `LLM-01..08` | 8 | Prompt-injection, retrieval and agent-tool abuse |
| `MUT-01` | 1 | Threat-model-aware mutation |
| `VER-01` | 1 | Fresh verifier that tries to disprove |
| `REP-01` | 1 | Report writer |
| `ORCH-01` | 1 | Bounded swarm orchestration |

Authorized targets only. Active payloads require a scope file naming the
allowed hosts, and every active test stops at the first reproducible proof.
See `VIBE-RUNBOOK.md` for the proof discipline and the safety addendum.
