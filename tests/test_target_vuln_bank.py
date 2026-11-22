"""Offline contract tests for the vuln-bank target harness.

No network, Docker or browser execution: every check reads the harness files or runs a
dry-run/refusal path that exits before cloning, starting containers or touching a target.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TARGET_DIR = REPO_ROOT / "targets" / "vuln-bank"
CLONE = TARGET_DIR / "clone.sh"
RUN = TARGET_DIR / "run.sh"
CHECKS = TARGET_DIR / "checks.json"
README = TARGET_DIR / "README.md"
DOC = REPO_ROOT / "docs" / "targets" / "vuln-bank.md"
SCOPE_EXAMPLE = TARGET_DIR / "scope.example.md"
PLAYWRIGHT_SPEC = TARGET_DIR / "playwright" / "vuln-bank.spec.js"

UPSTREAM_URL = "https://github.com/Commando-X/vuln-bank"
PINNED_COMMIT = "41c5b056f9ae8a8b15c77ea79f1419356b321634"

needs_sh = pytest.mark.skipif(shutil.which("sh") is None, reason="POSIX sh is required")


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def run_sh(*args: str, cwd: Path = REPO_ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sh", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


# --- pin and compose contract -------------------------------------------------


def test_pinned_upstream_is_recorded_everywhere() -> None:
    for path in (CLONE, RUN, CHECKS, README, DOC):
        text = read_text(path)
        assert UPSTREAM_URL in text, f"{path} does not name the upstream URL"
        assert PINNED_COMMIT in text, f"{path} does not record the pinned commit"
    assert "41c5b056f9ae8a8b15c77ea79f1419356b321634" == PINNED_COMMIT
    data = json.loads(read_text(CHECKS))
    assert data["upstream"] == {
        "url": UPSTREAM_URL,
        "clone_url": f"{UPSTREAM_URL}.git",
        "branch": "main",
        "commit": PINNED_COMMIT,
        "license": "MIT",
        "checkout": "vendor/external/vuln-bank",
    }


def test_compose_path_services_and_ports_are_recorded() -> None:
    data = json.loads(read_text(CHECKS))
    runtime = data["runtime"]
    assert runtime["compose_file"] == "docker-compose.yml"
    assert runtime["services"] == ["web", "db", "xss-cleaner", "autoheal"]
    assert runtime["database"] == "postgres:13"
    assert runtime["health"] == "/healthz"
    assert runtime["ports"] == {"web": 5000, "http": 80, "postgres": 5432}

    clone = read_text(CLONE)
    run = read_text(RUN)
    for text in (clone, run):
        assert "docker-compose.yml" in text
        assert "5000" in text
        assert "5432" in text
    assert "VULNBANK_WEB_PORT" in run
    assert "VULNBANK_HTTP_PORT" in run
    for service in runtime["services"]:
        assert service in clone, f"clone.sh does not verify the {service} service"


def test_run_binds_the_web_ports_to_loopback_by_default() -> None:
    text = read_text(RUN)
    assert "VULNBANK_WEB_PORT=127.0.0.1:" in text
    assert "VULNBANK_HTTP_PORT=127.0.0.1:" in text
    assert 'DEFAULT_TARGET="http://127.0.0.1:5000"' in text
    assert "--tunnel-url" in text


# --- shell syntax and clone behaviour ----------------------------------------


@needs_sh
@pytest.mark.parametrize("script", [CLONE, RUN], ids=["clone", "run"])
def test_shell_syntax(script: Path) -> None:
    result = run_sh("-n", str(script))
    assert result.returncode == 0, result.stderr


@needs_sh
def test_clone_dry_run_is_offline_and_prints_next_command(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    result = run_sh(str(CLONE), "--dry-run", "--dir", str(checkout))
    assert result.returncode == 0, result.stderr
    output = result.stdout
    assert UPSTREAM_URL in output
    assert PINNED_COMMIT in output
    assert "git clone" in output
    assert "docker-compose.yml" in output
    assert "sh targets/vuln-bank/run.sh" in output
    assert not checkout.exists(), "dry run must not create a checkout"


@needs_sh
def test_clone_refuses_to_overwrite_an_existing_checkout(tmp_path: Path) -> None:
    checkout = tmp_path / "existing"
    checkout.mkdir()
    kept = checkout / "kept.txt"
    kept.write_text("operator work\n", encoding="utf-8")

    result = run_sh(str(CLONE), "--dir", str(checkout))
    assert result.returncode != 0
    assert "refusing to overwrite" in result.stderr
    assert kept.read_text(encoding="utf-8") == "operator work\n"


@needs_sh
def test_clone_reuse_verifies_instead_of_resetting(tmp_path: Path) -> None:
    checkout = tmp_path / "not-a-checkout"
    checkout.mkdir()
    result = run_sh(str(CLONE), "--reuse", "--dir", str(checkout))
    assert result.returncode != 0
    assert "not a git checkout" in result.stderr


# --- run.sh behaviour ---------------------------------------------------------


@needs_sh
def test_run_dry_run_covers_the_documented_scenario(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    result = run_sh(str(RUN), "--dry-run", "--run-dir", str(run_dir))
    assert result.returncode == 0, result.stderr
    output = result.stdout
    for expected in (
        "vuln-bank harness (dry run)",
        "no Docker, no network, no browser",
        "scope.md",
        "threat-model.md",
        "sak plan --suite web-blackbox",
        "--step nuclei --dry-run",
        "npx playwright test",
        "sak findings import",
        "sak findings dedupe",
        "sak report",
        "docker compose up -d --build",
        PINNED_COMMIT,
    ):
        assert expected in output, f"dry-run output is missing: {expected}"
    assert not run_dir.exists(), "dry run must not create a run directory"


@needs_sh
def test_candidate_import_uses_findings_import(tmp_path: Path) -> None:
    text = read_text(RUN)
    assert "sak findings import" in text
    assert "sak findings add" not in text
    assert 'findings import "$RUN_DIR/findings/nuclei.json" --run-dir "$RUN_DIR"' in text

    result = run_sh(str(RUN), "--dry-run", "--run-dir", str(tmp_path / "run"))
    assert result.returncode == 0, result.stderr
    assert "sak findings import" in result.stdout
    assert "sak findings add" not in result.stdout


@needs_sh
def test_run_refuses_non_loopback_target_without_tunnel() -> None:
    result = run_sh(str(RUN), "--dry-run", "--target", "http://192.0.2.10:5000")
    assert result.returncode != 0
    assert "tunnel-url" in result.stderr


@needs_sh
def test_run_accepts_an_explicit_tunnel_origin(tmp_path: Path) -> None:
    result = run_sh(
        str(RUN),
        "--dry-run",
        "--tunnel-url",
        "http://legion.example:5000",
        "--run-dir",
        str(tmp_path / "run"),
    )
    assert result.returncode == 0, result.stderr
    assert "http://legion.example:5000" in result.stdout


@needs_sh
def test_run_rejects_bad_ports_and_purge_without_down() -> None:
    bad_port = run_sh(str(RUN), "--dry-run", "--port", "abc")
    assert bad_port.returncode != 0
    assert "--port" in bad_port.stderr

    purge = run_sh(str(RUN), "--dry-run", "--purge")
    assert purge.returncode != 0
    assert "--purge requires --down" in purge.stderr


# --- scenario contract --------------------------------------------------------


def test_scenarios_have_actions_and_safety_flags() -> None:
    data = json.loads(read_text(CHECKS))
    scenarios = data["scenarios"]
    assert len(scenarios) >= 12

    ids = [item["id"] for item in scenarios]
    assert len(ids) == len(set(ids)), "scenario ids must be unique"

    severities = {"low", "medium", "high", "critical"}
    methods_needing_approval = {"POST", "PUT", "PATCH", "DELETE"}
    destructive = ("rm -rf", "drop table", "truncate", "shutdown", "--volumes")

    for item in scenarios:
        assert item["id"].startswith("VB-")
        for key in ("title", "area", "cwe", "endpoint", "method", "tool", "action", "expected", "severity", "evidence"):
            assert item.get(key), f"{item['id']} is missing {key}"
        assert item["severity"] in severities
        assert "$TARGET" in item["action"] or item["endpoint"] in item["action"]
        action = item["action"].lower()
        for token in destructive:
            assert token not in action, f"{item['id']} looks destructive"
        if item["method"] in methods_needing_approval:
            assert item["approval_required"] is True, f"{item['id']} is a write and needs approval"

    brute = next(item for item in scenarios if item["id"] == "VB-AUTH-03")
    assert brute["approval_required"] is True
    assert brute["default"] is False


def test_docs_and_checks_contain_no_merchant_api_keys() -> None:
    for path in (CHECKS, README, DOC):
        text = read_text(path)
        assert "vk_" not in text, f"{path} contains a merchant API key"
        assert "DEEPSEEK_API_KEY=" not in text, f"{path} contains an API key value"


# --- repository hygiene, docs and scope --------------------------------------


def test_no_upstream_source_is_vendored_into_the_target_directory() -> None:
    assert "vendor/external/" in read_text(REPO_ROOT / ".gitignore")
    upstream_markers = {
        "app.py",
        "requirements.txt",
        "Dockerfile",
        "docker-compose.yml",
        "database.py",
        ".env",
    }
    present = {path.name for path in TARGET_DIR.rglob("*") if path.is_file()}
    assert not (upstream_markers & present), "upstream source must stay external"


def test_required_docs_and_operator_guide_cover_the_paths() -> None:
    readme = read_text(README)
    doc = read_text(DOC)
    for text in (readme, doc):
        assert UPSTREAM_URL in text
        assert PINNED_COMMIT in text
        assert "MIT" in text
        assert "5000" in text
        assert "5432" in text
        assert "docker compose down" in text
        assert "vendor/external/vuln-bank" in text
        assert "scope" in text.lower()
    for section in ("Test accounts", "Kali-local", "Mac tunnel"):
        assert section in doc, f"{DOC} is missing the {section} section"
    assert "admin" in doc and "ADMIN001" in doc
    assert "bookstore@vulnbank.org" in doc


def test_scope_example_is_parseable_and_bounded() -> None:
    scope = read_text(SCOPE_EXAMPLE)
    assert "## Allowed hosts" in scope
    assert "127.0.0.1:5000" in scope
    assert "localhost:5000" in scope
    assert "## Out of scope" in scope
    assert "max_requests:" in scope
    assert "max_seconds:" in scope
    assert "brute" in scope.lower()

    from sak.run import parse_scope_text

    parsed = parse_scope_text(scope, path=SCOPE_EXAMPLE)
    assert parsed.hosts == ("127.0.0.1:5000", "localhost:5000")
    assert parsed.errors == ()
    assert parsed.max_requests == 500
    assert parsed.max_seconds == 900


def test_playwright_spec_is_loopback_oriented_and_read_only() -> None:
    spec = read_text(PLAYWRIGHT_SPEC)
    assert "BASE_URL" in spec
    assert "healthz" in spec
    assert "localhost:5000" in spec or "127.0.0.1:5000" in spec
    for write_marker in ("request.post", "request.put", "request.delete", "page.click"):
        assert write_marker not in spec, f"smoke spec should stay read-only: {write_marker}"
