# Third-party notices — engines and reserve staples

This repository does not copy, vendor or redistribute code from any project listed here. The
engine cards and tool cards are metadata: a URL, a license name and the commands an operator may
choose to run on their own machine. Read the upstream license before you install anything.

Keeping GPL, AGPL and unlicensed projects external is this project's policy (`D-SAK-004`), not a
statement about what any license allows. Where a license could not be verified against a concrete
upstream revision, the row says so.

## Engines

| Project | Upstream | License | How we use it |
|---|---|---|---|
| T3MP3ST | https://github.com/elder-plinius/T3MP3ST | AGPL-3.0 | Optional external engine, cloned to `vendor/external/t3mp3st` (gitignored). Never vendored. |
| PentAGI | https://github.com/vxcontrol/pentagi | MIT (plus the repository's `EULA.md` for images/UI) | Optional external engine, cloned to `vendor/external/pentagi` (gitignored). Images are pulled from Docker Hub. Project site: https://pentagi.com |
| ARTEX | https://github.com/horizonl/ARTEX | AGPL-3.0 per the mirror's metadata (unverified) | Optional external engine, cloned to `vendor/external/artex` (gitignored). Upstream `Autumn-27/ARTEX` returned 404 on 2026-11-15; the mirror is not verified against a concrete upstream revision and its install path is not validated. |
| AppleResearch | https://github.com/dawgyg/AppleResearch | No license file visible (metadata missing, not adjudicated) | Reference only: a public dump of macOS research notes. No code, no copy, no install command. Kept reference-only by project policy; no statement is made about reuse rights. |

## Reserve staples catalogued by T9

| Project | Upstream | License | How we use it |
|---|---|---|---|
| ffuf | https://github.com/ffuf/ffuf | MIT | Host CLI, installed by the operator. No vendoring. |
| sqlmap | https://github.com/sqlmapproject/sqlmap | GPL-2.0 | Host CLI, external only. Never vendored, never bundled into a container we publish. |
| ZAP | https://github.com/zaproxy/zaproxy | Apache-2.0 | Host CLI or official container image. No source copied. |
| Playwright | https://github.com/microsoft/playwright | Apache-2.0 | npm dependency in the operator's own project; no browser binaries are committed. |
| Semgrep | https://github.com/semgrep/semgrep | LGPL-2.1 | Host CLI (OSS engine). No rules from the commercial registry are copied. |
| Gitleaks | https://github.com/gitleaks/gitleaks | MIT | Host CLI. No vendoring. |
| Trivy | https://github.com/aquasecurity/trivy | Apache-2.0 | Host CLI and its own vulnerability database at run time. No database copy in this repository. |

## Source decisions

`docs/source-decisions.md` records the disposition of every link the owner supplied, including
the ones owned by other tasks (`pwn-skill`, `security-audit`, Nuclei, Webseek, Blackbird, the Zenn
article, PortSwigger SSRF, the harness book and nip.io). Vendored MIT skills keep their own license
files and are recorded in the root `vendor/PROVENANCE.md` and root `THIRD_PARTY_NOTICES.md`, which
are owned by T2.

## Attribution requests

If you redistribute this repository, keep this file and the upstream license files that ship with
anything you choose to vendor. If a license changes upstream, update the card, this notice and the
source-decision row in the same commit.
