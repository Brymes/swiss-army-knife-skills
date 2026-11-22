# Engines — setup paths

T3MP3ST, PentAGI and ARTEX are **optional**. `sak` plans, runs and reports without any of them,
and v1 acceptance does not require Docker, an engine image or a provider key. The cards exist so
that an operator with a Docker host can add a heavy autonomous engine without changing the core.

The three setup paths differ in host, runtime and cost:

| Path | Host | Runtime needed | Engines it supports | Best for |
|---|---|---|---|---|
| A. Local npm | this Mac | Node 20+ and npm | T3MP3ST | A quick war room on the laptop, keyless with the coding agent |
| B. Local containers | this Mac | Docker Desktop or OrbStack | PentAGI, ARTEX, T3MP3ST | Reproducible compose stacks without touching the host |
| C. Remote Docker host (the Legion) | Linux box on the LAN | Docker Engine plus Compose | all three | Long runs, 16 GB+ memory, no laptop heat |

Everything the engines need is downloaded into `vendor/external/`, which is gitignored. No engine
tree, image or provider key is committed, and `sak` never installs a global tool.

## Common commands

```sh
uv run sak engine list                 # what cards exist
uv run sak engine doctor               # requirements per card, with hints
uv run sak engine doctor pentagi --json
uv run sak engine install pentagi       # dry run: prints the clone and .env copy
uv run sak engine install pentagi --execute
uv run sak engine up pentagi            # dry run
uv run sak engine up pentagi --execute
uv run sak engine status pentagi --execute
uv run sak engine down pentagi --execute
```

Dry run is the default and prints the exact shell command. `--execute` first re-checks
`requirements`; if anything is missing the command exits `2` and prints the requirement plus its
install hint, without a traceback and without a partial install. That refusal is the contract:
missing Docker, Compose, Node, Postgres or a provider key never becomes a half-started stack.

A shell wrapper adds a remote path and keeps the same default:

```sh
sh engines/scripts/host-check.sh                 # read-only host report, installs nothing
sh engines/scripts/engine.sh install pentagi      # dry run
sh engines/scripts/engine.sh install pentagi --execute
```

## Path A — local npm (T3MP3ST only)

Use this when you want to try the war room without Docker.

```sh
node --version        # 20 or newer; 22 is fine
npm --version
uv run sak engine install t3mp3st --execute   # git clone + npm install into vendor/external/t3mp3st
uv run sak engine up t3mp3st --execute        # npm run server (foreground)
# open http://127.0.0.1:3333/ui/ and connect Claude Code, Codex, OpenCode, Hermes or Oh My Pi
# stop it with Ctrl-C in that terminal; `sak engine down t3mp3st` refuses by design
```

Notes:

- Keyless by default: the connected coding agent is the model. A hosted key
  (`OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `VENICE_API_KEY`, `XAI_API_KEY`,
  `NOVITA_API_KEY`) or a local Ollama/llama.cpp endpoint is optional and belongs in
  `vendor/external/t3mp3st/.env`.
- The UI binds `127.0.0.1:3333`. Do not change that to `0.0.0.0`; use an SSH tunnel instead.
- Node 20+ is a practical floor, not a guarantee for every dependency. If `npm install` warns,
  re-run `npm --prefix vendor/external/t3mp3st run doctor`.

## Path B — local containers (Docker Desktop or OrbStack)

### Install a runtime (you do this, once)

Docker Desktop:

```sh
brew install --cask docker
open -a Docker            # start the daemon; wait for "Docker Desktop is running"
docker version
docker compose version
```

OrbStack (lighter, same CLI):

```sh
brew install --cask orbstack
open -a OrbStack
docker context use orbstack
docker version
```

Both provide the `docker` CLI and the `docker compose` plugin that the cards require. Pick one;
running both at once is a common source of "cannot connect to the daemon".

### Start an engine

```sh
uv run sak engine install pentagi --execute   # clones to vendor/external/pentagi and copies .env.example
# edit vendor/external/pentagi/.env: set one provider key or OLLAMA_SERVER_URL
uv run sak engine up pentagi --execute
uv run sak engine status pentagi --execute
# https://127.0.0.1:8443  (self-signed certificate)
uv run sak engine down pentagi --execute
```

```sh
# ARTEX: compose bundles PostgreSQL; set POSTGRES_PASSWORD and one provider key.
# Provenance is unverified: the upstream is 404 and the mirror has not been checked against a
# concrete revision, so re-verify the source and license before installing.
uv run sak engine install artex --execute
uv run sak engine up artex --execute
# http://127.0.0.1:8787 -> finish /setup with an admin password
uv run sak engine down artex --execute
```

### Apple `container`

The `container` CLI (macOS 26+, Apple silicon) runs Linux containers in lightweight VMs and is a
fine way to run a single image. It is **not** a Compose host: PentAGI and ARTEX need multi-service
Compose with health checks, volumes and a shared network, so use Docker Desktop, OrbStack or the
Legion for those. T3MP3ST's own compose file is a single API service, so a manual
`container run` is possible but unsupported by the card. `engines/scripts/host-check.sh` reports
whether `container` is present.

## Path C — the Legion (remote Docker host)

The Legion is a Linux machine on the LAN with Docker Engine and plenty of memory. Keep the repo
and the engines there; do not copy keys to the laptop.

```sh
ssh legion 'git -C ~/swiss-army-knife-skills pull --ff-only'   # only if you use a remote; never a push
ssh legion 'cd ~/swiss-army-knife-skills && uv sync && uv run sak engine doctor'
ssh legion 'cd ~/swiss-army-knife-skills && uv run sak engine up pentagi --execute'
```

With the wrapper:

```sh
export SAK_LEGION_HOST=legion
export SAK_ROOT=/home/you/swiss-army-knife-skills   # absolute path on the Legion
SAK_TARGET=legion sh engines/scripts/engine.sh up pentagi          # dry run: prints the ssh script
SAK_TARGET=legion sh engines/scripts/engine.sh up pentagi --execute
```

`SAK_ROOT` must be an absolute path on the remote host. The wrapper quotes it as one literal shell
word when it builds the remote script, so `~`, `$HOME` and other shell expansions are **not**
evaluated: `~/swiss-army-knife-skills` would be taken literally and `cd` would fail. Spaces and
single quotes inside an absolute path are handled safely by the quoting, but a tilde is not
expanded by design — use `ssh legion 'echo $HOME'` if you need the real path.

Reach a UI without exposing a port:

```sh
ssh -N -L 8443:127.0.0.1:8443 legion    # PentAGI
ssh -N -L 8787:127.0.0.1:8787 legion    # ARTEX
ssh -N -L 3333:127.0.0.1:3333 legion    # T3MP3ST
```

Then browse `https://127.0.0.1:8443` (PentAGI) or `http://127.0.0.1:8787` (ARTEX) on the laptop.
The tunnel is the only route in; nothing binds a public interface.

## Ports and data

| Engine | UI port | Other ports | Data on disk |
|---|---|---|---|
| T3MP3ST | 3333 | none published | `vendor/external/t3mp3st/` (missions, runs, `.env`) |
| PentAGI | 8443 (https) | flow sandboxes publish from `DOCKER_PORTS_BASE`, default 28000 | `vendor/external/pentagi/data/`, compose volumes |
| ARTEX | 8787 | none published | `vendor/external/artex/data/`, `vendor/external/artex/skills/`, compose volume for Postgres |

All three bind `127.0.0.1` by default. `data_paths` in each card lists the same locations so
`vendor/external/` can be deleted as one unit.

## Model and provider needs

- **T3MP3ST** is usable with no key: a connected coding agent, or Ollama/llama.cpp/LM Studio/vLLM
  through an OpenAI-compatible endpoint. Hosted keys are optional.
- **PentAGI** needs at least one provider: an API key (OpenAI, Anthropic, Gemini, Bedrock,
  DeepSeek, GLM, Kimi, Qwen, MiniMax, Mistral, xAI), a custom `LLM_SERVER_URL`, or a local Ollama.
  It also wants an embeddings provider for pgvector.
- **ARTEX** needs Anthropic or OpenAI (env or UI), or a custom `ARTEX_LLM_BASE_URL`.

Keys live in the engine's own `.env` under `vendor/external/`. `sak engine` masks secret-looking
values in output, but the card never stores one. See `docs/models.md` for choosing which model
serves which role.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `refused: missing runtime for pentagi: docker, docker compose` on `--execute` | No docker CLI or no compose plugin | Install Docker Desktop or OrbStack, start it, re-run `sak engine doctor` |
| `Cannot connect to the Docker daemon` | Daemon not running, or the wrong context | `open -a Docker` or `open -a OrbStack`; `docker context ls` |
| PentAGI UI shows a certificate warning | Compose serves https with a self-signed cert | Expected; the status check uses `curl -k`. Do not disable TLS on a shared host |
| PentAGI starts then exits | No provider key or endpoint | Set one key or `OLLAMA_SERVER_URL` in `.env`, then `docker compose logs pentagi` |
| ARTEX `setup` page returns 500 | `POSTGRES_PASSWORD` missing or the database is not healthy | Set it in `.env`, `docker compose down`, `up -d`, check `docker compose ps` |
| Port already in use | Another engine or a leftover container | `docker ps`, stop the old stack with `sak engine down`, or change the published port in the engine `.env` |
| `git clone` fails behind a proxy | No egress from the host | Configure the proxy for git and Docker, or use the Legion |

## What is deliberately out of scope

- Automatic mission execution against a target: the operator launches and reviews missions.
- Bundling an engine into `install.sh`, the wheel or a container we publish.
- Running any engine inside the core test suite. `tests/test_engines.py` uses a fake card and
  never touches the network.
- Any engine on a public interface, behind no authentication, with a real client's data.
