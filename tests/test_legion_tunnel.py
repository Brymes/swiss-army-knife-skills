"""Contract tests for scripts/legion-tunnel.sh.

The tunnel is an operator tool, so these tests never open a live SSH session.
Print-mode tests inspect the emitted command shape, and the ``--check`` path is
exercised with a fake ``ssh`` binary on ``PATH`` that records its argv.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "legion-tunnel.sh"
TARGET_DOC = ROOT / "targets" / "legion" / "README.md"
SCOPE_EXAMPLE = ROOT / "targets" / "legion" / "scope.example.md"
TAILSCALE_DOC = ROOT / "docs" / "targets" / "legion-tailscale.md"


def run_script(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    merged.update(env or {})
    return subprocess.run(
        ["sh", str(SCRIPT), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        env=merged,
    )


def tunnel_lines(result: subprocess.CompletedProcess[str]) -> list[str]:
    return [line for line in result.stdout.splitlines() if line.startswith("ssh -N -L ")]


def make_fake_ssh(tmp_path: Path, body: str = "echo OK\n") -> tuple[Path, Path]:
    """Create a fake ssh that records argv and never touches the network."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    args_file = tmp_path / "ssh-args.txt"
    fake = bindir / "ssh"
    fake.write_text(
        "#!/bin/sh\n"
        'printf \'%s\\n\' "$@" > "$FAKE_SSH_ARGS"\n'
        f"{body}",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    return bindir, args_file


def path_with(bindir: Path) -> str:
    return f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}"


def test_script_is_valid_posix_shell() -> None:
    result = subprocess.run(
        ["sh", "-n", str(SCRIPT)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_dry_run_prints_default_forward_commands() -> None:
    result = run_script("--dry-run")
    assert result.returncode == 0, result.stderr
    assert tunnel_lines(result) == [
        "ssh -N -L 8080:127.0.0.1:8080 legion-ts",
        "ssh -N -L 3000:127.0.0.1:3000 legion-ts",
        "ssh -N -L 8000:127.0.0.1:8000 legion-ts",
    ]


def test_default_mode_is_print_only_and_does_not_call_ssh(tmp_path: Path) -> None:
    bindir, args_file = make_fake_ssh(tmp_path)
    result = run_script(env={"PATH": path_with(bindir), "FAKE_SSH_ARGS": str(args_file)})
    assert result.returncode == 0, result.stderr
    assert len(tunnel_lines(result)) == 3
    assert not args_file.exists()


def test_custom_ports_and_host_are_used_verbatim() -> None:
    result = run_script("--dry-run", "8080", "9000")
    assert result.returncode == 0, result.stderr
    assert tunnel_lines(result) == [
        "ssh -N -L 8080:127.0.0.1:8080 legion-ts",
        "ssh -N -L 9000:127.0.0.1:9000 legion-ts",
    ]

    result = run_script("--dry-run", "--host", "legion-lab", "8443")
    assert result.returncode == 0, result.stderr
    assert tunnel_lines(result) == ["ssh -N -L 8443:127.0.0.1:8443 legion-lab"]


def test_invalid_ports_are_rejected() -> None:
    for bad in ("abc", "0", "65536", "80 80", "80;id"):
        result = run_script("--dry-run", bad)
        assert result.returncode != 0, bad
        assert "invalid port" in result.stderr, bad
        assert tunnel_lines(result) == [], bad


def test_invalid_hosts_are_rejected() -> None:
    for bad in ("", "-oProxyCommand=evil", "legion ts", "legion;id"):
        result = run_script("--dry-run", "--host", bad)
        assert result.returncode != 0, bad
        assert "invalid host" in result.stderr, bad
        assert tunnel_lines(result) == [], bad


def test_check_uses_fake_ssh_with_batch_mode_only(tmp_path: Path) -> None:
    bindir, args_file = make_fake_ssh(tmp_path)
    result = run_script(
        "--check",
        env={"PATH": path_with(bindir), "FAKE_SSH_ARGS": str(args_file)},
    )
    assert result.returncode == 0, result.stderr
    assert "OK" in result.stdout
    argv = args_file.read_text(encoding="utf-8").splitlines()
    assert argv == ["-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "legion-ts", "echo OK"]
    assert "-N" not in argv


def test_check_honours_a_custom_host(tmp_path: Path) -> None:
    bindir, args_file = make_fake_ssh(tmp_path)
    result = run_script(
        "--check",
        "--host",
        "legion-lab",
        env={"PATH": path_with(bindir), "FAKE_SSH_ARGS": str(args_file)},
    )
    assert result.returncode == 0, result.stderr
    argv = args_file.read_text(encoding="utf-8").splitlines()
    assert argv[-2:] == ["legion-lab", "echo OK"]


def test_unknown_option_is_rejected() -> None:
    result = run_script("--definitely-not-a-flag")
    assert result.returncode != 0
    assert "unknown option" in result.stderr


def test_target_docs_cover_both_supported_paths() -> None:
    readme = TARGET_DOC.read_text(encoding="utf-8")
    for phrase in (
        "Kali WSL",
        "SSH tunnel",
        "Tailscale",
        "userspace",
        "WARP",
        "Windows firewall",
        "Docker",
        "DVWA",
        "8080",
        "vuln-bank",
    ):
        assert phrase in readme, phrase


def test_scope_example_names_loopback_ports_and_boundaries() -> None:
    scope = SCOPE_EXAMPLE.read_text(encoding="utf-8")
    for phrase in ("Authorization", "In scope", "Out of scope", "8080", "legion-ts"):
        assert phrase in scope, phrase
    assert "127.0.0.1" in scope


def test_tailscale_doc_has_required_troubleshooting_sections() -> None:
    doc = TAILSCALE_DOC.read_text(encoding="utf-8")
    for phrase in (
        "## Troubleshooting",
        "ssh legion-ts",
        "WSL ports do not",
        "Windows firewall",
        "portproxy",
        "tailscale status",
        "tailscale ping",
        "When to run inside Kali instead",
    ):
        assert phrase in doc, phrase
