# Legion targets — Mac and Kali WSL paths

> **Example name.** “Legion” and `legion-ts` are the example remote-lab host and
> SSH alias used by this repository. Replace them with your own host and alias.

This directory documents the two supported ways to run the suite against the
authorized Legion target. Both keep the target on loopback as seen by the
sending host. Neither path scans the public internet, a third-party service or
another Tailscale node.

The two paths are:

1. **Suite inside Kali WSL (preferred).** Kali and the Docker targets share the
   Ubuntu/Kali WSL network namespace, so `127.0.0.1:8080` reaches DVWA and the
   vuln-bank containers directly. No tunnel is needed.
2. **Suite on the Mac with an SSH tunnel.** The suite runs on macOS and reaches
   Legion loopback ports through local forwards opened by
   [`scripts/legion-tunnel.sh`](../../scripts/legion-tunnel.sh).

Read [`docs/targets/legion-tailscale.md`](../../docs/targets/legion-tailscale.md)
before debugging connectivity, and copy [`scope.example.md`](scope.example.md)
to a run directory only after it names the real authorized host.

## Network context

- Legion is reached over Tailscale. `legion-ts` is the expected SSH alias; it is
  a host alias, not a public DNS name.
- Tailscale may run in **userspace mode** (no kernel TUN device), or the Windows
  host may use **WARP** alongside Tailscale. Both can make ICMP behave unlike
  TCP. Treat `tailscale ping` and `ssh` as separate checks.
- MagicDNS must resolve `legion-ts`, or the SSH config must define it. Check
  `tailscale status` on both ends when the alias stops resolving.
- SSH key authentication is expected. Do not put passwords in scripts, shell
  history, scope files or reports.

## Path 1 — suite inside Kali WSL

Use this when the suite, Docker and the targets all live in the same WSL
distribution.

1. Confirm Kali is the active WSL distribution and that Docker is reachable
   inside it (`docker info`). Docker Desktop integration or a Docker daemon in
   the Ubuntu/Kali WSL distribution is fine; the daemon must be the one the
   shell can talk to.
2. Start the targets as loopback-only containers. Publish DVWA on `8080` and
   vuln-bank on its documented ports. The repository uses these placeholders:
   - DVWA: `8080`
   - vuln-bank API/UI: `3000` and `8000` (replace with the ports printed by your
     compose file; the tunnel defaults mirror them only as placeholders)
3. Verify from inside WSL: `curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/`.
4. Run `uv run sak ...` from the repository checkout inside Kali with
   `http://127.0.0.1:8080` in scope.

No `ssh -L` tunnel is required on this path. A tunnel from Windows into WSL is a
different mechanism and usually points at the wrong network namespace.

Known limit: Windows firewall rules and WSL's NAT do not automatically expose
WSL-published ports to the Windows host or to Legion. That is why
`ssh legion-ts` can work while `http://legion-ts:8080` does not. Run the suite
inside WSL instead of opening the port.

## Path 2 — suite on the Mac with an SSH tunnel

Use this when the suite runs on macOS and the targets run on Legion.

1. Confirm SSH reaches Legion with key auth: `ssh legion-ts 'echo OK'`.
2. Print the forwards without opening anything:
   `sh scripts/legion-tunnel.sh --dry-run`
3. Print custom forwards: `sh scripts/legion-tunnel.sh --dry-run 8080 9000`
4. Start them in the foreground and leave the terminal open:
   `sh scripts/legion-tunnel.sh --execute`
5. In a second terminal, verify `curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/`.
6. Put `http://127.0.0.1:8080` (not the Legion hostname) in the run scope.

Each forwarded port maps to the Legion host's own loopback:
`ssh -N -L 8080:127.0.0.1:8080 legion-ts`. The script validates ports and the
host alias, never prompts for or stores a password, and does not use `eval` or
rebuild a command string. `--check` is the only mode that contacts the host; it
runs a bounded BatchMode probe and is never part of a dry run.

## Target map

| Target | Legion loopback port | Scope URL from the Mac | Scope URL inside Kali WSL |
|---|---|---|---|
| DVWA | `8080` | `http://127.0.0.1:8080` via tunnel | `http://127.0.0.1:8080` |
| vuln-bank (placeholder) | `3000` | `http://127.0.0.1:3000` via tunnel | `http://127.0.0.1:3000` |
| vuln-bank (placeholder) | `8000` | `http://127.0.0.1:8000` via tunnel | `http://127.0.0.1:8000` |

The vuln-bank ports are placeholders because the external compose file owns
them. Change the scope and the tunnel arguments together; do not widen the scope
to cover guesses.

## Safety

- Authorized loopback targets or the named Legion path only.
- DVWA and vuln-bank credentials belong in ignored `.env` files. This directory
  contains no credentials.
- Stop the tunnel when the run ends; a forgotten `-L` keeps a port open.
- If a fix needs a Windows `portproxy` rule or a firewall change that requires
  administrator rights, stop and ask the engagement owner first.
