# Vendor provenance

Two third-party agent skills are vendored into `vendor/skills/` under the MIT
license. Upstream content is copied verbatim: only the `.git` directory is
excluded, and the Cloudflare skill is placed at the root of its local directory
so the skill directory contains `SKILL.md` (see *File mapping* below). No
upstream file body, frontmatter, reference document, schema or validator was
edited, reformatted or renamed.

Machine-readable pins and per-file SHA-256 checksums live in
[`sources.lock.json`](sources.lock.json). That file is the recorded manifest
checked by `tests/test_vendor.py`.

## Pinned sources

| Skill | Upstream URL | Default branch | Pinned commit | Commit date | License | Local path |
|---|---|---|---|---|---|---|
| `pwn-hunter` | <https://github.com/BountyForge-xyz/pwn-skill> | `main` | `403310598eab3c99c24082795c35b76e790ed6a5` | 2026-11-06 | MIT (BountyForge-xyz) | `vendor/skills/pwn-hunter/` |
| `security-audit` | <https://github.com/cloudflare/security-audit-skill> | `main` | `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` | 2026-09-14 | MIT (Cloudflare, Inc.) | `vendor/skills/security-audit/` |

Both commits were resolved with `git ls-remote --symref <url> HEAD` on
2026-11-15, before any file was copied, and the cloned commit was re-checked
with `git rev-parse HEAD` afterwards. Both matched the resolved SHA.

Fetch date for both copies: **2026-11-15T09:45:18Z**.

## Copy method

```sh
git clone --depth 1 https://github.com/BountyForge-xyz/pwn-skill .tmp-vendor/pwn-skill
git clone --depth 1 https://github.com/cloudflare/security-audit-skill .tmp-vendor/security-audit-skill

rsync -a --exclude '.git' .tmp-vendor/pwn-skill/ vendor/skills/pwn-hunter/
rsync -a .tmp-vendor/security-audit-skill/skills/security-audit/ vendor/skills/security-audit/
cp .tmp-vendor/security-audit-skill/LICENSE vendor/skills/security-audit/LICENSE
```

The temporary clones under `.tmp-vendor/` were removed after the checksum
manifest was recorded; nothing from them is committed.

### File mapping

| Upstream path | Local path | Notes |
|---|---|---|
| `pwn-skill/SKILL.md`, `README.md`, `LICENSE`, `assets/banner.svg`, `.gitignore` | `vendor/skills/pwn-hunter/<same>` | Upstream layout preserved at the repository root. |
| `security-audit-skill/skills/security-audit/*` | `vendor/skills/security-audit/*` | All 20 upstream files: `SKILL.md`, 14 reference documents, `report-schema.json`, two validators and their two tests. |
| `security-audit-skill/LICENSE` | `vendor/skills/security-audit/LICENSE` | Upstream MIT license kept beside the skill. |

`vendor/skills/security-audit/` therefore is the upstream skill directory
(`skills/security-audit/`) plus the upstream `LICENSE`. This is the layout an
agent skill needs: one directory whose `SKILL.md` is its entry point. The
upstream repository-root `README.md` is not copied because it documents the
repository, not the skill, and is not part of `skills/security-audit/`.

## Upstream content is unmodified

The vendored files are byte-for-byte copies. The only differences from upstream
are the excluded `.git` directory and the destination directory names. The
checksums in `sources.lock.json` are the evidence: `tests/test_vendor.py::
test_copied_files_match_manifest` recomputes SHA-256 for every vendored file and
fails on any drift.

Do not edit files under `vendor/skills/`. To pick up an upstream change, refresh
the pin (new commit, new checksums, new fetch date) in one commit and note it
here.

## Integration contract

### Discovery after `install.sh`

`install.sh` (T10) links skills into an agent-visible skill directory:
`.opencode/skills/` for a project-local install or `~/.agents/skills/` for a
global install. Each vendored skill is exposed as one directory whose
`SKILL.md` sits at that directory's root:

```text
.opencode/skills/pwn-hunter/      -> vendor/skills/pwn-hunter/
.opencode/skills/security-audit/  -> vendor/skills/security-audit/
.opencode/skills/swiss-army-knife/ -> skills/swiss-army-knife/
```

The skill name an agent reports comes from the `name` field in `SKILL.md`
frontmatter (`pwn-hunter` and `security-audit`). The local directory names match
those names, which keeps discovery, catalog IDs and provenance aligned.

### Delegation from the `swiss-army-knife` skill (T4)

- **Source audits** go to `security-audit`. When a target is a repository or a
  source tree, T4 hands the absolute target path and the selected attack classes
  to the `security-audit` skill and follows its six-phase workflow
  (reconnaissance, coverage-led hunting, candidate validation, structured
  output, independent record verification, reporting). T4 does not restate or
  rewrite the audit methodology; it passes scope, target and budget, then maps
  the returned `confirmed` / `needs_validation` / `rejected` records into the
  `sak` findings model and report.
- **Binary work** goes to `pwn-hunter`. When the target includes a native
  binary, a crash sample or a memory-corruption lead in an authorized lab, T4
  delegates to `pwn-hunter` for triage, primitive identification and a measured
  `exp.py` proof of concept. T4 keeps the surrounding engagement context and
  records the primitive, offset and observed result as evidence; it does not
  re-author the exploit chain guidance.

Both delegations stay inside the `sak` safety contract: authorized targets only,
no live external targets, no destructive or denial-of-service payloads, and
`security-audit` target-controlled execution only inside an OS-enforced sandbox
as its `SKILL.md` requires.

### Runtime expectations

- `pwn-hunter` needs Python 3 with `pwntools` plus a debugger (`pwndbg`/`gef`);
  `ROPgadget`, `ropper`, `one_gadget`, `seccomp-tools` and `patchelf` are
  optional. These are host tools, not vendored, and are never installed by a
  worker: `sak doctor` prints the install hints.
- `security-audit` needs Node.js for `validate-findings.cjs` and
  `validate-coverage-ledger.cjs`. The validators are zero-dependency and are
  invoked as `node vendor/skills/security-audit/<validator>.cjs <path>`.

## License notices

The required third-party notices are in [`../THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).
Both licenses are MIT and are compatible with this repository's MIT license.
No GPL, AGPL or unlicensed code is vendored.
