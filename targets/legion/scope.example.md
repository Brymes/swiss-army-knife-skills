# Scope — Legion DVWA and vuln-bank (example)

Copy this file into `runs/<run-id>/scope.md` and replace every placeholder with
the real engagement values. An unfilled placeholder is not a scope.

- Authorization: <who authorized this, and where the permission is recorded>
- In scope:
  - `http://127.0.0.1:8080` — DVWA, reached through a local SSH tunnel or from
    inside Kali WSL
  - `http://127.0.0.1:3000` — vuln-bank placeholder port; confirm the actual
    published port before the run
  - `http://127.0.0.1:8000` — vuln-bank placeholder port; confirm the actual
    published port before the run
  - Transport: `ssh -N -L <port>:127.0.0.1:<port> legion-ts` on the Mac, or
    direct loopback inside the Kali/Ubuntu WSL distribution
- Methods: GET, HEAD, OPTIONS, POST (documented writes only)
- Accounts: seeded DVWA and vuln-bank test users only, never a real customer.
  Credentials live in ignored `.env` files or the target's own setup notes.
- Out of scope:
  - Any host other than the three loopback URLs above
  - The Legion host itself, other Tailscale nodes, MagicDNS names and the
    Tailscale control plane
  - Cloud metadata, third-party APIs, denial of service, destructive writes
  - Real personal data and social engineering
- Window: <date and time range>
- Rate: 1 request/second; stop on 5xx or a state change outside the plan
- Budget: primary 3, support 4, fallback 3, brute 0
- Approval: <name> for any brute card or state-changing replay
- Tunnel: start with `sh scripts/legion-tunnel.sh --dry-run`, then
  `--execute`; stop the tunnel when the run ends. `--check` is optional and
  contacts only `legion-ts`.

## Notes

- Do not widen the scope to `legion-ts`, `*.ts.net` or a LAN subnet.
- Do not add a Windows `portproxy` rule or firewall exception without owner
  approval.
- If the suite runs on the Mac, the scope names `127.0.0.1`; the tunnel is an
  implementation detail, not permission to reach Legion's other ports.
