# Kali MCP, optional

Kali MCP is **optional**. The `swiss-army-knife` skill is a shell-and-files skill;
it does not require an MCP server, a specific Kali image or a particular harness.
MCP only changes where the tool calls run.

This repository does **not** ship or vendor a Kali MCP server. Use your harness's
server or a reviewed external one.

## 1. Choose a mode

| Mode | Command runs in | Best for |
|---|---|---|
| Local shell | The same machine as the repo | macOS, Linux, WSL, CI |
| Kali WSL shell | Kali WSL distribution | Docker-published labs on `127.0.0.1` |
| SSH tunnel | Local shell, targets on a remote lab | macOS with a remote Docker host |
| Kali MCP | Kali VM/container through the harness | An agent that only has MCP tools |

The evidence contract is identical in every mode: a `scope.md`, bounded requests,
sanitized artifacts under `runs/`, `sak verify`, and `sak report`.

## 2. Minimum MCP tool surface

A Kali MCP server is sufficient when the harness can:

1. **Execute a command** in the repository checkout with a bounded timeout.
2. **Read and write files** under the checkout (scope, profiles, evidence).
3. **Reach loopback** on the Kali host (`127.0.0.1:8080`, `127.0.0.1:5000`).
4. Optionally run **Docker** for the local labs.
5. Optionally drive a **browser** for Playwright checks.

If the server can only execute commands, the skill can still use the CLI and write
evidence through shell redirection. A browser tool is only needed for browser
proofs; otherwise those checks stay `needs_validation`.

## 3. Generic configuration

MCP configuration shapes differ by harness. The following is illustrative; replace
the command, args and workspace with your server's contract.

```json
{
  "mcpServers": {
    "kali": {
      "command": "<your-kali-mcp-server>",
      "args": ["--workspace", "/workspace/swiss-army-knife-skills"],
      "env": {
        "NEAR_AI_API_KEY": "${NEAR_AI_API_KEY}"
      }
    }
  }
}
```

Rules:

- Mount **only** the repository workspace, not the whole host filesystem.
- Set the workspace and command `cwd` to the repository root.
- Pass model keys through the environment; never put them in a prompt or a card.
- Use a non-root user in the Kali container/VM when possible.
- Allow outbound network only to the authorized lab, or none for the offline demo.

## 4. Setup check

Run these through the MCP `exec` tool before the first assessment:

```sh
pwd
uv --version
uv sync
uv run sak --version
uv run sak doctor
uv run sak catalog validate
docker ps                 # optional, only for local labs
curl -fsS http://127.0.0.1:8080/login.php -o /dev/null && echo dvwa-ok
curl -fsS http://127.0.0.1:5000/healthz && echo vuln-bank-ok
```

If `pwd` is not the repository root, fix the workspace mount before continuing.
If `uv` or Docker is missing, `sak doctor` prints the install hint; the skill does
not install global tools.

## 5. Run through MCP

Ask the agent to use the skill and keep the same command sequence:

```text
Use the swiss-army-knife skill through the Kali MCP server.
Workspace: /workspace/swiss-army-knife-skills
Target: http://127.0.0.1:8080
Create the scope, run the DVWA profile checks, verify the rubric and render the
report. Keep evidence under runs/ and mask secrets.
```

The agent should call the MCP `exec` tool with:

- `cwd` = repository root;
- a bounded timeout per command;
- no interactive prompts;
- stdout/stderr captured and masked;
- `uv run sak ...` commands, not a bare `sak` from an unknown PATH.

A typical sequence:

```sh
mkdir -p runs/mcp-dvwa
cat > runs/mcp-dvwa/scope.md <<'EOF'
# Scope — DVWA Low through Kali MCP
## In scope
- http://127.0.0.1:8080
## Out of scope
- Any non-loopback host
## Budget
- max_requests: 400
- max_seconds: 900
EOF

uv run sak exploit --run runs/mcp-dvwa \
  --target http://127.0.0.1:8080 \
  --profile targets/dvwa/blackbox/profile.yaml --json
uv run sak verify --run runs/mcp-dvwa \
  --profile targets/dvwa/blackbox/profile.yaml --json
uv run sak report runs/mcp-dvwa
```

## 6. No MCP

Use the local shell directly.

### Kali WSL

```sh
cd /path/to/swiss-army-knife-skills
uv sync
uv run sak exploit --run runs/dvwa-kali \
  --target http://127.0.0.1:8080 \
  --profile targets/dvwa/blackbox/profile.yaml --json
```

### macOS with a remote lab

Forward the lab loopback ports, then use `127.0.0.1` in the scope:

```sh
ssh -N -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
  -L 8080:127.0.0.1:8080 <your-lab-host>

ssh -N -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
  -L 15000:127.0.0.1:5000 <your-lab-host>
```

vuln-bank uses `http://127.0.0.1:15000` on the Mac; DVWA uses
`http://127.0.0.1:8080`. Port `5000` on macOS is often AirTunes, so do not use it
for vuln-bank there. The full path is in [blackbox-pilot.md](blackbox-pilot.md).

## 7. Tool mapping

| Skill need | MCP tool | Notes |
|---|---|---|
| `uv run sak ...` | `exec` / shell | one command per call, bounded timeout |
| read `scope.md`, profiles | file read | workspace-relative paths |
| write evidence/report | file write or shell redirect | keep under `runs/` |
| readiness check | `exec` + `curl` | loopback only |
| browser proof | browser tool | optional; otherwise `needs_validation` |
| lab lifecycle | Docker tool or `exec docker` | optional and explicit |

## 8. Safety

- The MCP server often has host access. Treat it as a privileged tool.
- Authorized targets only. A scope file is mandatory before active checks.
- No destructive or denial-of-service payloads by default.
- No real credentials, customer data or third-party targets.
- No root shell unless the lab explicitly requires it.
- Keep the workspace mount narrow; do not expose the user's home directory.
- Mask tokens, cookies, keys and card data in every artifact.
- Stop the MCP server and any forwards when the engagement ends.

## 9. Troubleshooting

| Symptom | Check |
|---|---|
| `uv: command not found` | Install `uv` in the Kali image or use the harness path |
| `sak` not found | Use `uv run sak`, or install with `uv sync` |
| command runs in `/` | Set the MCP workspace and `cwd` to the repo root |
| lab unreachable | `curl` loopback inside Kali; check Docker port mapping |
| browser checks skipped | Add a browser MCP tool or accept `needs_validation` |
| child writes outside `runs/` | Start `sak hunt` from `runs/<run>/scratch` |
| model key missing | Set it in the MCP env, not the prompt |
