# Legion over Tailscale — operator notes

> **Example name.** “Legion” and `legion-ts` are the example remote-lab host and
> SSH alias used by this repository. Replace them with your own host and alias.

Short operator guide for reaching the authorized Legion DVWA and vuln-bank
targets from a Mac or from Kali WSL. Long-form target setup lives in
[`targets/legion/README.md`](../../targets/legion/README.md).

## Choose a path

- **Run inside Kali WSL** when possible. The suite and the Docker-published
  targets share one network namespace, so loopback URLs just work.
- **Run on the Mac** when the suite must stay on macOS. Use
  `scripts/legion-tunnel.sh` to forward Legion loopback ports to Mac loopback.

```sh
# Print only; opens nothing.
sh scripts/legion-tunnel.sh --dry-run

# Print custom ports.
sh scripts/legion-tunnel.sh --dry-run 8080 9000

# Open the forwards in the foreground.
sh scripts/legion-tunnel.sh --execute

# Optional, bounded, and the only mode that contacts the host.
sh scripts/legion-tunnel.sh --check
```

The forward shape is always:

```text
ssh -N -L <port>:127.0.0.1:<port> legion-ts
```

## Troubleshooting

### `ssh legion-ts` works but WSL ports do not

This is the common case, not a Tailscale failure. `ssh` proves TCP reachability
to the Windows/WSL SSH service. A service bound to `127.0.0.1` inside a WSL
distribution is not reachable from the Windows host or from another Tailscale
node by default. WSL's NAT also means a Windows-side forward can point at the
wrong interface.

Options, in order of preference:

1. Run the suite inside the same WSL distribution as the targets. This avoids
   the Windows-to-WSL hop entirely and is the supported path.
2. Bind the target to the WSL interface that Tailscale/Windows can reach, then
   confirm with `curl` from the Windows host. This widens the target's exposure;
   update the scope first.
3. Add a Windows `portproxy` rule only with owner approval, because it needs
   administrator rights and creates a new listening surface.

### Windows firewall and portproxy

- A Windows firewall rule may allow `22/tcp` while silently dropping `8080`,
  `3000` or `8000`.
- `netsh interface portproxy` rules require an elevated shell, are easy to leave
  behind, and are not a default fix. If one is genuinely required, stop and ask
  the engagement owner; record the exact rule and its removal step.
- Docker Desktop's WSL integration publishes ports in a different network
  namespace than a Docker daemon running inside Ubuntu/Kali WSL. `docker port`
  in the same shell that runs the suite must show the expected mapping.

### Tailscale status

Check both ends:

```sh
tailscale status
tailscale ip -4
```

What to look for:

- `legion-ts` (or the configured alias) is listed and online.
- The Mac and Legion are in the same tailnet.
- MagicDNS resolves the alias. If it does not, fix the SSH config or use the
  Tailscale IP; do not add a public DNS record.
- Userspace mode or WARP may be active. In userspace mode there may be no kernel
  route for ICMP, so a failed `ping` is not proof that TCP is down.

### `tailscale ping`

```sh
tailscale ping legion-ts
```

`tailscale ping` tests the Tailscale path, not the target service and not
loopback inside WSL. A reply means the nodes can see each other; a timeout with
a working `ssh` points at the WSL/Windows boundary instead. Use `ssh -v` and
`curl -v http://127.0.0.1:<port>/` to separate the two.

### When to run inside Kali instead

Move the suite into Kali WSL when any of these is true:

- `ssh legion-ts` succeeds but `curl http://legion-ts:<port>/` or a tunnel to a
  WSL-published port fails.
- The target only listens on `127.0.0.1` inside WSL.
- A fix would need a Windows firewall exception or an elevated `portproxy` rule.
- Docker runs inside Ubuntu/Kali WSL rather than through Docker Desktop.

Running inside Kali removes the Windows-to-WSL hop and keeps every target on
loopback. It also keeps the scope narrow: `http://127.0.0.1:8080`.

## Safety

- Authorized loopback targets or the named Legion path only.
- No passwords, tokens or private keys in commands, notes, evidence or reports.
  Use SSH keys and ignored `.env` files.
- Stop forwards with Ctrl-C; verify with `ssh`/`curl` rather than leaving a
  forgotten `-L` open.
- Do not change firewall, `portproxy` or Tailscale ACL settings without owner
  approval.
