# Catalog

Catalog YAML is the source of truth. Every card is validated against a JSON
Schema in `../schemas/`; generated indexes are never hand-edited. The loader
reads every `*.yaml` / `*.yml` file under `catalog/` and infers the card type
from its directory.

```
catalog/
  tools/     one tool / skill / platform / service / reference / mcp card per file
  prompts/   one prompt card per file
  suites/    one suite card per file
  sources/   one source-decision card per file
  models.yaml  model profiles (single card, list, or {models: [...]})
```

Cards may also be stored as a list, or under a plural key (`tools:`, `prompts:`,
`suites:`, `sources:`, `engines:`, `models:`, `cards:`, `items:`).

## Commands

```sh
uv run sak catalog list [--kind KIND] [--status STATUS] [--domain DOMAIN] [--json]
uv run sak catalog show <id> [--json]
uv run sak catalog search <text> [--json]
uv run sak catalog validate [--catalog DIR] [--json]
uv run sak catalog export [--json]
```

`validate` checks required fields, allowed values, duplicate IDs (catalog-wide)
and suite references to tools and prompts. It exits `1` on any issue and prints
every problem it found.

## ID rules

- Tool, suite, source, engine and model IDs: `^[a-z0-9][a-z0-9._-]*$`.
- Prompt IDs: `^[A-Z][A-Z0-9]*-[0-9]{2}$`, such as `INV-01`, `VIBE-14`,
  `SSRF-08`, `LLM-01`, `MUT-01`, `VER-01`, `REP-01`.
- IDs are unique across the whole catalog.

## Tool card

Required: `id`, `name`, `kind`, `status`, `description`, `domains`, `phases`,
`intensity`, `ranking`.

- `kind`: `skill`, `cli`, `platform`, `service`, `reference`, `mcp`.
- `status`: `verified`, `unverified`, `experimental`, `deprecated`. Only
  `verified` cards are planned automatically.
- `domains`: `web`, `api`, `source`, `binary`, `cloud`, `osint`, `macos`,
  `llm`, `network`, `mobile`.
- `phases`: `recon`, `discovery`, `scan`, `exploit`, `post`, `verify`,
  `report`, `setup`.
- `modes` (optional): `blackbox`, `greybox`, `whitebox`, `source`, `binary`,
  `passive`. Absent means suitable for any mode.
- `intensity`: `passive`, `normal`, `brute`. `brute` cards are held in reserve.
- `roles` (optional): `primary`, `support`, `fallback`, `brute`, `triage`,
  `evidence`.
- `ranking`: integers `1..5` for `impact`, `reliability`, `stealth`, `effort`
  and `noise`. Higher `effort` and `noise` reduce the score.
- `requires`: executable names, `docker compose`, python module names such as
  `pwntools`, or `ENV_VAR` names. Missing requirements exclude a card from a
  plan unless `--allow-missing-requires` is passed.
- `install` / `run`: a string or `{command, args, url, manager, notes}`.
- `adapter`: adapter name when `sak run` can execute the card, otherwise null.
- `safety`: `{active, intrusive, destructive, notes}`.
- `sources`: `[{url, license, note}]`.

## Ranking formula

```text
score = 2*impact + reliability + stealth - effort - noise
```

The plan prints the formula, each card's score and its five components, so a
ranking can be explained without rerunning the planner. Ties break on card ID.

## Suite card

Required: `id`, `name`, `description`, `profile`, `filters`.

- `profile`: `web-blackbox`, `web-source`, `binary`, `api-blackbox`, `custom`.
- `filters`: `kinds`, `statuses`, `domains`, `modes`, `requires`, `tags`,
  `exclude_ids`.
- `include.tools` / `include.prompts`: explicit IDs that bypass kind, domain,
  mode and tag filters (schema and existence still apply).
- `budget`: `primary`, `support`, `fallback`, `brute` role caps. Defaults are
  `3/4/3/1`.
- If `filters.statuses` is omitted, only `verified` cards are eligible.

## Prompt card

Required: `id`, `title`, `category`, `description`, `domains`, `hunter_role`,
`prompt`.

- `category`: `invariant`, `vibe`, `ssrf`, `llm`, `mutation`, `verification`,
  `report`, `orchestration`.
- `hunter_role`: `primary`, `support`, `fallback`, `brute`, `triage`,
  `evidence`.
- Optional: `applies_to`, `intensity`, `when_to_use`, `inputs`, `mutations`,
  `evidence`, `stop_conditions`, `safety`, `tags`, `source`, `notes`.

## Source, engine and model cards

- Source: required `id`, `name`, `url`, `type`, `license`, `decision`,
  `rationale`. `type` and `decision` are `vendor`, `adapter`, `engine`,
  `reference` or `external`.
- Engine: required `id`, `name`, `description`, `license`, `requirements`,
  `commands` (`install`, `up`, `down`, `status`). Commands are dry-run by
  default; `sak engine <action> --execute` is required to run them. Missing
  Docker, Compose, Node, Postgres or API keys produce a clean refusal (exit
  `2`), never a traceback. Secret-looking env values, auth headers and
  `key=value` credentials are masked in dry-run and result output; the original
  command and environment are still passed to the subprocess.
- Model: required `id`, `name`, `provider`, `role`, `description`. `role` is
  `hunting`, `generation`, `verification`, `reporting`, `mutation`,
  `orchestration` or `embedding`.

## Adding a card

1. Copy an existing card in the matching directory.
2. Choose a unique ID and fill every required field.
3. Run `uv run sak catalog validate`.
4. Run `uv run sak plan --catalog catalog --suite <suite> --target <url>`
   to confirm it ranks as intended.

Test fixtures live in `tests/fixtures/catalog/` and stay offline. They are not
production cards.
