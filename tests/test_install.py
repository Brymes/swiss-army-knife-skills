"""Contract tests for install.sh.

The installer is a shell script; these tests run it in dry-run mode only. They
assert the plan, the license policy and that no filesystem change or secret
leakage happens. Real installation is an operator action.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "install.sh"


def run_install(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    merged.update(env or {})
    return subprocess.run(
        ["sh", str(INSTALL), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        env=merged,
    )


def test_install_script_exists_and_is_executable_by_shell() -> None:
    assert INSTALL.is_file()
    result = run_install("--help")
    assert result.returncode == 0
    assert "--dry-run" in result.stdout
    assert "--local" in result.stdout
    assert "--global" in result.stdout


def test_dry_run_plans_uv_sync_and_mit_skills_only() -> None:
    before = (ROOT / ".opencode").exists()
    result = run_install("--dry-run")
    assert result.returncode == 0, result.stderr
    output = result.stdout
    assert "dry-run: no filesystem changes" in output
    assert "would sync: uv sync" in output
    assert f"would link: swiss-army-knife (MIT)" in output
    assert "would link: pwn-hunter (MIT)" in output
    assert "would link: security-audit (MIT)" in output
    assert "refused: 0" in output
    # A dry run must not create the local skill directory.
    assert (ROOT / ".opencode").exists() == before


def test_global_dry_run_targets_the_user_skill_directory(tmp_path: Path) -> None:
    home = tmp_path / "home"
    result = run_install("--global", "--dry-run", env={"HOME": str(home)})
    assert result.returncode == 0, result.stderr
    assert f"{home}/.agents/skills" in result.stdout
    assert not (home / ".agents").exists()


def test_dry_run_does_not_echo_environment_secrets() -> None:
    marker = "sak-install-secret-should-never-print"
    result = run_install("--dry-run", env={"SAK_INSTALL_TEST_SECRET": marker})
    assert result.returncode == 0, result.stderr
    assert marker not in result.stdout
    assert marker not in result.stderr


def test_unknown_option_is_rejected() -> None:
    result = run_install("--definitely-not-a-flag")
    assert result.returncode != 0
    assert "unknown option" in result.stderr


def test_installer_source_declares_license_policy_and_modes() -> None:
    text = INSTALL.read_text(encoding="utf-8")
    assert "GNU AFFERO GENERAL PUBLIC LICENSE" in text
    assert "GNU GENERAL PUBLIC LICENSE" in text
    assert "MIT License" in text
    assert "vendor/skills" in text
    assert "ln -sfn" in text
