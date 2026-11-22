# Changelog

All notable changes are recorded here. The format is loosely based on Keep a
Changelog; versions use semantic versioning.

## [0.1.0] - 2026-11-22

Initial public release.

### Added

- Catalog-first CLI (`sak`) for tools, prompts, suites, engines, models and sources.
- Ranked planning with role waves and budgeted execution.
- Deterministic localhost fixture evaluation and report rendering.
- Findings model with `confirmed`, `needs_validation` and `rejected` verdicts.
- Adapters and optional external engines, dry-run by default.
- `sak hunt` bounded prompt-hunter runner with a provider-neutral model/runner
  contract.
- `sak exploit` profile-driven HTTP proof engine.
- `sak verify` rubric verification, coverage scoring and evidence hashing.
- MIT `swiss-army-knife`, `security-audit` and `pwn-hunter` skills.
- OpenCode local/global skill install.
- Harness/model integration docs, optional Kali MCP guide and no-MCP path.
- DVWA Low and vuln-bank benchmark records with 15/15 and 11/11 rubric coverage.
- CI for offline tests and catalog validation.

### Security

- Scope gate for active tools.
- Secret masking in evidence and reports.
- No real credentials in the repository or benchmark records.
