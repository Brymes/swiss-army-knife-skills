# Source decisions

One row per link the owner supplied, plus the reserve staples this task catalogued. Each row
records what the source is, its license as observed, and the disposition sak chose. Checked on
2026-11-15 where the upstream was reachable; a row that could not be verified against a concrete
upstream revision says so. License terms and project policy are separate: this project's policy
(`D-SAK-004`) keeps GPL, AGPL and unlicensed code out of the repository. That is a policy choice,
not a claim about what any license permits.

Decisions:

- **vendor** — the source is copied into the repository with its license and provenance. MIT only.
- **adapter** — we write our own adapter and call the external tool or service; no source copied.
- **engine** — an optional external system with an engine card; installed by the operator under
  the gitignored `vendor/external/`.
- **reference** — reading material or a service used in payloads; no code executed from it.
- **external** — a real tool we run from the host but never copy into the repository.

AGPL-3.0, GPL-2.0, GPL-3.0 and unlicensed material never enters this repository. That is an owner
decision (`D-SAK-004`) and the reason several good tools are `external` or `engine` rather than
`vendor`.

## Owner links

| Link | Type | License | Decision | URL | Rationale |
|---|---|---|---|---|---|
| pwn-skill | vendor | MIT | vendor | https://github.com/BountyForge-xyz/pwn-skill | Binary-exploitation agent skill. MIT permits vendoring; T2 copies it to `vendor/skills/pwn-hunter/` with provenance. |
| security-audit | vendor | MIT | vendor | https://github.com/cloudflare/security-audit-skill | Cloudflare's multi-phase audit skill and its verdict model. MIT; T2 vendors it and T6 reuses the confirmed/needs_validation/rejected vocabulary. |
| Nuclei | external | MIT | adapter | https://github.com/projectdiscovery/nuclei | The web/API scanner the planner leans on. We write an adapter with JSONL parsing rather than copying templates or the Go tree. |
| PentAGI | external | MIT | engine | https://github.com/vxcontrol/pentagi | Heavy autonomous agent stack (project site https://pentagi.com). MIT source plus a separate `EULA.md` for images and UI; it stays an external engine under `vendor/external/pentagi`. |
| Webseek | external | MIT | adapter | https://github.com/dyoshikawa/webseek | npm `webseek` 0.6.0, Node 20+, multi-provider search CLI and MCP server. An adapter wraps `npx`; keys stay in the operator's environment. |
| T3MP3ST | external | AGPL-3.0 | engine | https://github.com/elder-plinius/T3MP3ST | AGPL-3.0. Project policy keeps AGPL code out of this MIT repository, so it is an optional external engine cloned to `vendor/external/t3mp3st`. Never vendored. |
| Blackbird | external | not established (no root license visible; T5 brief metadata previously recorded GPL-3.0) | external | https://github.com/antoniaci/blackbird | OSINT username/email search, formerly `p1ngul1n0/blackbird`. The license is unresolved: no root license was visible in the senior check and the API reports none, so the GPL-3.0 claim is prior brief metadata, not a verified fact. External-only and T5 owns the card; do not reuse a license claim in notices until a concrete upstream file and revision are cited. |
| AppleResearch | external | none declared | external | https://github.com/dawgyg/AppleResearch | macOS research notes with no LICENSE file. Reference only: no code copied, no install step, v1 does not execute macOS work. Absence of a license file is recorded as observed metadata, not a legal conclusion. |
| ARTEX | external | AGPL-3.0 per the mirror's repository metadata (unverified) | engine | https://github.com/horizonl/ARTEX | Autonomous pentest system. The project's own upstream (`Autumn-27/ARTEX`) returned 404 on 2026-11-15. The `english-ui` mirror is not verified by the senior's primary-source check, is not presented as maintained or trusted, and its install path is not validated. External only, operator re-verification required. |
| Zenn article | reference | site copyright | reference | https://zenn.dev/team_zenn/articles/opencode-docker-actions-ai-pentest | A Japanese engineering article on an OpenCode/Docker/GitHub Actions pentest pipeline. We summarise the pattern in `knowledge/methodology/ci-pentest-harness.md`; no text is copied and no `sak ci` mode is built in v1. |
| PortSwigger SSRF | reference | site copyright | reference | https://portswigger.net/web-security/ssrf | The SSRF learning material behind the T3 payload set. Concepts and public technique only; the payload cards are written in our own words with local-fixture tests. |
| harness book | reference | book copyright | reference | https://grahamhelton.github.io/harness-engineering-workshop-book/print.html | *Introduction To Harness Engineering For Vulnerability Research* (Helton, Basden). Our notes in `knowledge/methodology/harness-engineering.md` are a summary in our own words, not a copy. |
| nip.io | reference | free service terms | reference | https://nip.io | Wildcard DNS used in SSRF payloads (`127.0.0.1.nip.io` and friends). A third-party service, never a dependency: T3 and T8 resolve it only against the local fixture. |

## Reserve staples catalogued by T9

| Link | Type | License | Decision | URL | Rationale |
|---|---|---|---|---|---|
| ffuf | external | MIT | external | https://github.com/ffuf/ffuf | Content and parameter fuzzing. Host CLI, brute reserve; nothing copied. |
| sqlmap | external | GPL-2.0 | external | https://github.com/sqlmapproject/sqlmap | Injection detection. Project policy (`D-SAK-004`) keeps GPL code out of the repository, so this is an external binary, never vendored or bundled. The card pins `--risk=1 --level=1`. |
| ZAP | external | Apache-2.0 | external | https://github.com/zaproxy/zaproxy | Broad DAST second opinion. Apache-2.0 permits vendoring but the app, add-ons and browser bundles make that pointless; run the cask or the official image. |
| Playwright | external | Apache-2.0 | external | https://github.com/microsoft/playwright | Browser-behaviour verification. We depend on it in the operator's project; browser binaries are never committed. |
| Semgrep | external | LGPL-2.1 | external | https://github.com/semgrep/semgrep | Source-code pattern scanning. LGPL engine stays an external binary; no registry rules are copied. |
| Gitleaks | external | MIT | external | https://github.com/gitleaks/gitleaks | Passive secret scanning. MIT, but a single statically linked binary is easier to run than to vendor, and it must stay current. |
| Trivy | external | Apache-2.0 | external | https://github.com/aquasecurity/trivy | Dependency, image and IaC scanning. Downloads its own advisory database at run time, so vendoring the binary would not make it offline. |

## How this is enforced

`tests/test_engines.py` parses both tables and fails when a required link row is missing, a
decision is outside the allowed set, a license cell is empty, a URL is not `https`, an engine
card's source is not recorded here, or a T9 tool card's source is recorded neither here nor in
`engines/THIRD_PARTY_NOTICES.md`. A license change upstream must update the card, the notice and
the row in the same commit.

## Known limits

- Licenses were read from repository metadata, a `LICENSE`/`COPYING` file or an npm manifest on
  2026-11-15 where reachable. They were not reviewed by counsel, and an absent license file is
  recorded as missing metadata, not adjudicated. A vendoring decision needs the license text in
  `vendor/`, which T2 owns.
- Blackbird: the GitHub API reports no license and the senior's check found none in the visible
  root or README. T5's brief previously recorded GPL-3.0 plus a CC BY-NC-SA notice; that is prior
  brief metadata, not a verified upstream fact. The `external` decision holds either way, and T5
  owns the card and its notices.
- AppleResearch has no license file. This row records that observation and stops there; it makes
  no legal claim about reuse.
- ARTEX: the upstream is 404 and the mirror is unverified. The engine card marks the provenance as
  unverified and the install path as unvalidated. If the mirror disappears, mark the card
  deprecated rather than substituting a new one without a fresh check.
- T3MP3ST, PentAGI and ARTEX were not installed or started here (Docker is absent on this host),
  so engine `status: unverified` reflects untested operation, not a failed check.
