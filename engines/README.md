# Engines

Optional, heavy, external assessment engines. **No engine is required for v1 acceptance** and
none of them is installed by `uv sync`, `install.sh` or `sak doctor`.

```
engines/
  t3mp3st.yaml            engine card: commands, ports, data paths, refusal contract
  pentagi.yaml
  artex.yaml
  README.md               this file
  THIRD_PARTY_NOTICES.md  licenses and provenance for everything the cards point at
  scripts/
    host-check.sh         reports Docker/Compose/Node/Postgres availability; installs nothing
    engine.sh             dry-run wrapper around `sak engine <action> <id>`
```

An engine card is data, not code. `sak engine` reads it, checks `requirements` with the same
detector `sak doctor` uses, and prints the commands. Nothing runs unless `--execute` is passed, and
`--execute` refuses (exit `2`) when a requirement is missing or the card has no command for the
action.

```sh
uv run sak engine list                  # table
uv run sak engine list --json           # machine-readable
uv run sak engine doctor                # requirement check, all engines
uv run sak engine doctor pentagi --json
uv run sak engine install pentagi        # dry run: prints the clone and .env copy
uv run sak engine up pentagi --execute   # real run, after the requirements check
uv run sak engine down pentagi --execute
```

Cards live here, outside `catalog/`, because they are operational definitions rather than catalog
entries; the matching tool cards (`catalog/tools/pentagi.yaml`, `t3mp3st.yaml`, `artex.yaml`)
describe ranking, domains and safety for the planner.

## Rules the cards follow

1. **External only.** T3MP3ST and ARTEX are AGPL-3.0; project policy keeps GPL/AGPL code under
   `vendor/external/`, which is gitignored, rather than in the repository. PentAGI is MIT but still runs from that directory so no engine image or tree enters
   the repository.
2. **No automatic installs.** `sak` never installs a global tool. The commands are shown first;
   the operator runs them.
3. **No secrets in cards.** Provider keys go in the engine's own `.env` under `vendor/external/`.
   Engine output is masked, but the card never contains a value.
4. **Loopback first.** Every published port is `127.0.0.1`. Reach a remote host through an SSH
   tunnel, not by exposing the port.
5. **Clean refusal.** Missing Docker, Compose, Node, Postgres or a provider key produces exit `2`
   with the requirement and an install hint. See `docs/engines.md` for the exact paths and host
   options.
