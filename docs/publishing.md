# Publishing to GitHub

Maintainer checklist for a clean public release. The public repo is
<https://github.com/Brymes/swiss-army-knife-skills>.

## 1. Prepare a clean release branch

Internal agent packs, worktrees and run evidence are not part of the public tree.
Use an orphan branch so old local history never reaches GitHub.

```sh
git status --short
git checkout --orphan public-release

# Move internal workflow artifacts out of the tree (or delete them).
mv .durable-pack /tmp/sak-durable-pack-backup
rm -rf .agent-workpacks worktrees tests/fixtures/verify
find . -name .DS_Store -delete

git add -A
git status --short
```

`.gitignore` keeps `.durable-pack/`, `.agent-workpacks/`, `worktrees/`, `runs/*`,
`.opencode/` and generated fixtures out of the commit.

## 2. Scan for PII and secrets

Run all of these before the first push and again before a release:

```sh
# Absolute user paths and internal pack paths
git grep -nE '/Users/|C:\\\\Users|\.durable-pack|\.agent-workpacks' -- . ':!vendor' || true

# Common token shapes and lab credentials
git grep -nE 'eyJ[A-Za-z0-9_-]{8,}\.|vk_[A-Za-z0-9]{8,}|sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}' || true
git grep -nE 'admin123|SakLab[AB]123!|VbProd_2026|VulnBankAdmin_2025|ds_live_|PHPSESSID=[A-Za-z0-9]{8,}' || true

# Local-only files
git ls-files | grep -E '^(runs/|worktrees/|\.durable-pack/|\.opencode/|node_modules/|\.venv/)' && echo 'unexpected local path' || true
find . -name .DS_Store -o -name '*.pyc' | head
```

Expected remaining emails are documented lab or fixture addresses such as
`*@example.test` and the public vuln-bank demo accounts. They are not personal
data. Everything under `runs/` is gitignored and remains local evidence.

## 3. Verify the public tree

```sh
uv sync
uv run pytest -q
uv run sak catalog validate
uv run sak doctor
git ls-tree -r --name-only HEAD | wc -l
```

The offline suite must pass with no Docker, no model key and no network.

## 4. Create the GitHub repository

The repository should not already exist. Create it empty so the first push is the
clean orphan commit.

```sh
gh repo create Brymes/swiss-army-knife-skills \
  --public \
  --description "Portable, ranked security-tool and prompt suite for authorized assessments"

git remote add origin https://github.com/Brymes/swiss-army-knife-skills.git
git push -u origin public-release:main
```

If a remote already exists, inspect it before pushing:

```sh
git remote -v
git push --dry-run origin public-release:main
```

Never force-push a public `main` without coordination.

## 5. Repository settings

```sh
gh repo edit Brymes/swiss-army-knife-skills \
  --add-topic security \
  --add-topic penetration-testing \
  --add-topic ai-agents \
  --add-topic opencode \
  --add-topic mcp \
  --add-topic python

gh repo edit Brymes/swiss-army-knife-skills --enable-issues --enable-wiki=false
```

Recommended settings:

- default branch `main`;
- require the CI check before merge;
- enable private vulnerability reporting (see `SECURITY.md`);
- enable Dependabot alerts;
- protect `main` from force-pushes once contributors join.

## 6. Release

```sh
git tag -a v0.1.0 -m "sak 0.1.0 — initial public release"
git push origin v0.1.0
gh release create v0.1.0 --title "sak 0.1.0" \
  --notes-file CHANGELOG.md
```

The release notes must state the benchmark honestly: 15/15 vuln-bank and 11/11
DVWA Low **rubric coverage**, not "all vulnerabilities".

## 7. Post-publish check

```sh
gh repo view Brymes/swiss-army-knife-skills
gh run list --limit 5
git ls-tree -r --name-only origin/main | grep -E '\.durable-pack|/Users/|runs/' && echo 'leak' || true
```

Open the README, `docs/skill-usage.md`, `docs/harness-integration.md`,
`docs/kali-mcp.md`, `docs/benchmark.md` and the CI badge in a private browser
window to confirm the public rendering.

## 8. Local branch hygiene

The orphan release branch can become the local `main` after the push:

```sh
git branch internal-main main          # keep the old local history, never push it
git branch -f main public-release
git checkout main
```

Keep the internal branch local or delete it once the evidence is archived. Do not
push it.

## 9. License and provenance

- The repository is MIT (`LICENSE`).
- Vendored skills are MIT with their own licenses and pins in
  `vendor/PROVENANCE.md`, `vendor/sources.lock.json` and
  `THIRD_PARTY_NOTICES.md`.
- GPL, AGPL and unlicensed code is never vendored. Optional engines stay external
  and gitignored.
- Do not add a dependency or vendor a skill without updating the notices.
