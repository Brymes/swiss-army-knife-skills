# Contributing

Thanks for helping improve `sak`. The project is MIT licensed and welcomes issues,
pull requests, catalog cards and documentation fixes.

## 1. Set up

```sh
git clone https://github.com/Brymes/swiss-army-knife-skills.git
cd swiss-army-knife-skills
uv sync
uv run sak doctor
uv run sak catalog validate
uv run pytest -q
```

Python 3.12 is managed by `uv`. Docker and Node are optional. The test suite, demo
and local fixture use loopback only.

Install the skills for your harness:

```sh
sh install.sh --local     # ./.opencode/skills
sh install.sh --global    # ~/.agents/skills
```

Read [docs/skill-usage.md](docs/skill-usage.md),
[docs/harness-integration.md](docs/harness-integration.md) and
[docs/kali-mcp.md](docs/kali-mcp.md) before changing the skill or its install
contract.

## 2. What to run

| Change | Required check |
|---|---|
| Python code | `uv run pytest -q` |
| Catalog card or schema | `uv run sak catalog validate` |
| Skill text or docs | `uv run pytest tests/test_skill_docs.py tests/test_blackbox_pilot_docs.py -q` |
| Exploit/verify/report behavior | `uv run pytest tests/test_exploit.py tests/test_verify.py -q` |
| Benchmark record | `uv run pytest tests/test_skill_docs.py -q` and a live loopback rerun |

The full suite must stay green. Tests are offline by default; do not add a test
that needs Docker, a public host, a paid API or a real credential.

## 3. Catalog rules

The catalog YAML is the source of truth. Do not hand-edit generated indexes.

- Add or change a tool, prompt, suite, engine, model or source card in `catalog/`.
- Validate against the JSON Schema in `schemas/`.
- Use `status: verified` only after a measured run; otherwise use `unverified` or
  `experimental`.
- Keep `requires` honest; `sak doctor` uses it.
- No GPL, AGPL or unlicensed code. Optional engines stay external and gitignored.
- Keep the scoring inputs explainable; do not tune a score to make a card win.

See [docs/adding-tools.md](docs/adding-tools.md).

## 4. Skill changes

The entry point is `skills/swiss-army-knife/SKILL.md`. Keep it harness-neutral:

- no vendor-specific tool names unless they are optional examples;
- no hardcoded API keys, hosts or user paths;
- no claim that `sak` calls a model when it does not;
- no `confirmed` language for a hunter candidate;
- keep the scope gate, dry-run rule and evidence contract intact.

Vendored skills in `vendor/skills/` are pinned MIT copies. Do not edit them in
place; update the pin, license and `THIRD_PARTY_NOTICES.md` together.

## 5. Safety and privacy

- Authorized targets only. Active tools require a `scope.md`.
- No destructive or denial-of-service payloads by default.
- No real credentials, cookies, keys, customer data or personal information in
  code, tests, docs, evidence, logs or benchmark records.
- Use loopback fixtures and documented lab defaults.
- Mask tokens, cookies, authorization headers and card data in reports.
- A new live benchmark entry must be secret-free and reproducible from a profile.

## 6. Pull requests

1. Open an issue for a behavior change or a new integration.
2. Keep the change focused; one concern per PR.
3. Add or update tests and docs.
4. Run the checks in section 2.
5. Describe the target, scope and evidence if the change is security-facing.
6. Confirm no secrets or PII in the diff.

Commit messages use a short conventional prefix (`feat:`, `fix:`, `docs:`,
`test:`, `chore:`). By contributing, you agree that your contribution is licensed
under the repository's MIT license.

## 7. Reporting a security issue in `sak`

Do not open a public issue for a vulnerability in `sak` itself. Follow
[SECURITY.md](SECURITY.md). Findings about a target belong in that target's run
report, not in the `sak` issue tracker.

## 8. Code of conduct

All participation is covered by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
