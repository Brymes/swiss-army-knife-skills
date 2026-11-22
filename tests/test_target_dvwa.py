"""Offline checks for the DVWA low-security target harness.

These tests never start Docker, launch a browser or contact a target. They
validate the compose file, the Playwright scenario, shell syntax, dry-run
behavior, secret hygiene and the documentation required for both the Kali WSL
and Mac tunnel paths.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import types
from pathlib import Path

import pytest
import yaml

from sak.run import parse_scope_text, scope_allows

ROOT = Path(__file__).resolve().parents[1]
DVWA = ROOT / "targets" / "dvwa"
COMPOSE = DVWA / "compose.yaml"
SETUP = DVWA / "setup.sh"
RUN = DVWA / "run.sh"
CHECKS = DVWA / "checks.json"
README = DVWA / "README.md"
DOCS = ROOT / "docs" / "targets" / "dvwa.md"
ENV_EXAMPLE = DVWA / ".env.example"


def _shell(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sh", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def _values(document: object) -> list[str]:
    if isinstance(document, dict):
        return [value for item in document.values() for value in _values(item)]
    if isinstance(document, list):
        return [value for item in document for value in _values(item)]
    return [str(document)]


def _load_t1_adapter() -> types.ModuleType:
    """Load the T1 Playwright adapter without merging another task's files.

    The T3 branch predates T1, so the merged adapter is read from the local
    checkout when present and otherwise from the ``main`` git object.  In the
    integrated tree the local file wins and this is a normal import.
    """
    local = ROOT / "adapters" / "playwright.py"
    if local.is_file():
        source = local.read_text(encoding="utf-8")
        label = str(local)
    else:
        result = subprocess.run(
            ["git", "show", "main:adapters/playwright.py"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            pytest.skip("the T1 Playwright adapter is not present in this checkout")
        source = result.stdout
        label = "main:adapters/playwright.py"

    module = types.ModuleType("sak_t1_playwright_contract")
    module.__file__ = label
    exec(compile(source, label, "exec"), module.__dict__)
    return module


def test_compose_uses_named_loopback_container_and_healthcheck() -> None:
    data = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    services = data.get("services")
    assert isinstance(services, dict) and "dvwa" in services
    dvwa = services["dvwa"]

    assert dvwa["image"] == "vulnerables/web-dvwa"
    assert dvwa["container_name"] == "sak-dvwa"
    ports = [str(port) for port in dvwa["ports"]]
    assert ports == ["127.0.0.1:${DVWA_PORT:-8080}:80"]
    assert all("0.0.0.0" not in port for port in ports)

    healthcheck = dvwa["healthcheck"]
    assert isinstance(healthcheck["test"], list)
    assert healthcheck["test"][0] == "CMD-SHELL"
    assert "fsockopen" in healthcheck["test"][1]
    assert int(healthcheck["retries"]) >= 1
    assert "start_period" in healthcheck

    text = COMPOSE.read_text(encoding="utf-8")
    assert "network_mode: host" not in text
    assert "privileged: true" not in text


def test_env_example_documents_the_demo_defaults() -> None:
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    assert "DVWA_PORT=8080" in text
    assert "DVWA_URL=http://127.0.0.1:8080" in text
    assert "DVWA_USERNAME=admin" in text
    assert "DVWA_PASSWORD=password" in text
    assert "ignored by git" in text

    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".env" in ignored
    assert ".env.*" in ignored
    assert "!.env.example" in ignored


def test_scenario_contract_covers_login_security_and_vulnerable_pages() -> None:
    data = json.loads(CHECKS.read_text(encoding="utf-8"))
    assert data["target"] == "${DVWA_URL}"
    assert "steps" in data and "actions" not in data
    steps = data["steps"]
    names = [step["action"] for step in steps]
    for required in (
        "goto",
        "fill",
        "click",
        "select",
        "expect_url",
        "expect_text",
        "expect_status",
        "wait_for",
        "screenshot",
    ):
        assert required in names, f"scenario is missing {required}"

    gotos = [step["url"] for step in steps if step["action"] == "goto"]
    assert all(url.startswith("${DVWA_URL}/") for url in gotos)
    for path in ("/login.php", "/security.php", "/vulnerabilities/sqli/", "/vulnerabilities/xss_r/"):
        assert any(url.endswith(path) for url in gotos), f"scenario never visits {path}"

    fills = {step["selector"]: step["value"] for step in steps if step["action"] == "fill"}
    assert fills['input[name="username"]'] == "${DVWA_USERNAME}"
    assert fills['input[name="password"]'] == "${DVWA_PASSWORD}"

    selects = [step for step in steps if step["action"] == "select"]
    assert any(
        step["selector"] == 'select[name="security"]' and step["value"] == "low"
        for step in selects
    )
    assert any(
        step["action"] == "wait_for"
        and step["selector"] == 'select[name="security"]'
        for step in steps
    )
    wait_steps = [step for step in steps if step["action"] == "wait_for"]
    assert all(
        "option[" not in step.get("selector", "") for step in wait_steps
    ), "hidden option selectors cannot be waited on"
    assert any(
        step["action"] == "expect_text" and "Security Level" in step.get("text", "")
        for step in steps
    )

    statuses = [step["status"] for step in steps if step["action"] == "expect_status"]
    assert statuses.count(200) >= 3
    texts = " ".join(step["text"] for step in steps if step["action"] == "expect_text")
    assert "SQL Injection" in texts
    assert "Cross Site Scripting" in texts
    assert "Logout" in texts

    values = {value.lower() for value in _values(data)}
    assert "admin" not in values
    assert "password" not in values
    assert "Authorization" not in CHECKS.read_text(encoding="utf-8")


def test_checks_json_matches_the_t1_scenario_contract() -> None:
    adapter = _load_t1_adapter()
    scenario = adapter.load_scenario(CHECKS)

    assert "actions" not in scenario
    assert isinstance(scenario["steps"], list) and scenario["steps"]
    actions = {step["action"] for step in scenario["steps"]}
    assert actions <= set(adapter.SCENARIO_ACTIONS)

    expect_urls = [step for step in scenario["steps"] if step["action"] == "expect_url"]
    assert expect_urls
    assert all("contains" in step for step in expect_urls), "exact expect_url matches are brittle"


def test_shell_scripts_parse_with_sh_n() -> None:
    for script in (SETUP, RUN):
        result = _shell("-n", str(script.relative_to(ROOT)))
        assert result.returncode == 0, result.stderr
        assert result.stderr == ""


def test_nuclei_nonzero_is_recorded_and_playwright_still_runs(tmp_path: Path) -> None:
    fake_sak = tmp_path / "fake-sak"
    calls = tmp_path / "sak-calls.txt"
    fake_sak.write_text(
        """#!/bin/sh
printf '%s\\n' "$*" >> "$SAK_CALLS"
run_dir=
prev=
for arg in "$@"; do
  if [ "$prev" = "--run-dir" ] || [ "$prev" = "--run" ]; then run_dir=$arg; fi
  prev=$arg
done
case "$*" in
  plan\\ *|*" plan "*)
    cat > "$run_dir/plan.json" <<'JSON'
{"target": "http://127.0.0.1:9", "candidates": [{"id": "nuclei"}, {"id": "playwright"}]}
JSON
    ;;
  *" --step nuclei "*)
    mkdir -p "$run_dir/findings" "$run_dir/steps" "$run_dir/logs"
    printf '%s\\n' '[]' > "$run_dir/findings/nuclei.json"
    printf '%s\\n' '{"step": "nuclei"}' > "$run_dir/steps/nuclei.json"
    printf '%s\\n' 'nuclei timed out' > "$run_dir/logs/nuclei.log"
    exit 17
    ;;
esac
exit 0
""",
        encoding="utf-8",
    )
    fake_sak.chmod(0o755)

    run_dir = tmp_path / "run"
    environment = os.environ.copy()
    environment["SAK_CMD"] = str(fake_sak)
    environment["SAK_CALLS"] = str(calls)
    environment["DVWA_SKIP_SETUP"] = "1"
    result = subprocess.run(
        [
            "sh",
            "targets/dvwa/run.sh",
            "--no-compose",
            "--url",
            "http://127.0.0.1:9",
            "--run-dir",
            str(run_dir),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        env=environment,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    transcript = calls.read_text(encoding="utf-8").splitlines()
    nuclei = next(index for index, line in enumerate(transcript) if "--step nuclei" in line)
    playwright = next(index for index, line in enumerate(transcript) if "--step playwright" in line)
    assert playwright < nuclei
    assert any("findings import" in line and "nuclei.json" in line for line in transcript)
    assert any("findings import" in line and "playwright.json" in line for line in transcript)
    assert any(line.startswith("report ") for line in transcript)

    warning = run_dir / "logs" / "nuclei-warning.txt"
    assert warning.is_file()
    warning_text = warning.read_text(encoding="utf-8")
    assert "nuclei step exited 17" in warning_text
    assert "continuing to candidate import and report" in warning_text
    assert (run_dir / "findings" / "nuclei.json").is_file()
    assert (run_dir / "steps" / "nuclei.json").is_file()
    assert "warning: nuclei exited 17" in result.stderr


def test_budget_exhausting_nuclei_does_not_block_playwright(tmp_path: Path) -> None:
    fake_sak = tmp_path / "fake-sak"
    calls = tmp_path / "sak-calls.txt"
    fake_sak.write_text(
        """#!/bin/sh
printf '%s\\n' "$*" >> "$SAK_CALLS"
run_dir=
prev=
for arg in "$@"; do
  if [ "$prev" = "--run-dir" ] || [ "$prev" = "--run" ]; then run_dir=$arg; fi
  prev=$arg
done
case "$*" in
  plan\\ *|*" plan "*)
    cat > "$run_dir/plan.json" <<'JSON'
{"target": "http://127.0.0.1:9", "candidates": [{"id": "nuclei"}, {"id": "playwright"}]}
JSON
    ;;
  *" --step playwright "*)
    if [ -f "$run_dir/budget.json" ]; then
      echo "refused: remaining 0 requests" >&2
      exit 23
    fi
    ;;
  *" --step nuclei "*)
    mkdir -p "$run_dir/findings" "$run_dir/logs"
    printf '%s\\n' '{"requests": 500, "max_requests": 500}' > "$run_dir/budget.json"
    printf '%s\\n' '[]' > "$run_dir/findings/nuclei.json"
    exit 17
    ;;
esac
exit 0
""",
        encoding="utf-8",
    )
    fake_sak.chmod(0o755)

    run_dir = tmp_path / "run"
    environment = os.environ.copy()
    environment["SAK_CMD"] = str(fake_sak)
    environment["SAK_CALLS"] = str(calls)
    environment["DVWA_SKIP_SETUP"] = "1"
    result = subprocess.run(
        [
            "sh",
            "targets/dvwa/run.sh",
            "--no-compose",
            "--url",
            "http://127.0.0.1:9",
            "--run-dir",
            str(run_dir),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        env=environment,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    transcript = calls.read_text(encoding="utf-8").splitlines()
    nuclei = next(index for index, line in enumerate(transcript) if "--step nuclei" in line)
    playwright = next(index for index, line in enumerate(transcript) if "--step playwright" in line)
    assert playwright < nuclei, "Playwright must run before the budget-consuming Nuclei scan"
    assert any("findings import" in line and "playwright.json" in line for line in transcript)
    assert any(line.startswith("report ") for line in transcript)
    assert (run_dir / "budget.json").is_file()
    assert (run_dir / "logs" / "nuclei-warning.txt").is_file()


def test_setup_dry_run_is_offline_and_prints_no_credentials() -> None:
    result = _shell("targets/dvwa/setup.sh", "--dry-run")
    assert result.returncode == 0, result.stderr
    output = result.stdout
    assert "dry run: DVWA setup" in output
    assert "http://127.0.0.1:8080" in output
    assert "create or reset" in output
    assert "security=low" in output
    assert "no request was sent" in output
    assert "password=password" not in output.lower()
    assert "PHPSESSID" not in output


def test_generated_scope_is_accepted_by_the_scope_gate() -> None:
    run_text = RUN.read_text(encoding="utf-8")
    match = re.search(r'cat > "\$RUN_DIR/scope\.md" <<SCOPE\n(.*?)\nSCOPE\n', run_text, re.S)
    assert match is not None, "run.sh no longer writes a SCOPE heredoc"

    target = "http://127.0.0.1:18080"
    scope_text = match.group(1).replace("$URL", target)
    assert "## In scope" in scope_text
    assert f"| {target} | web |" in scope_text

    scope = parse_scope_text(scope_text)
    assert scope.errors == ()
    assert scope.hosts == ("127.0.0.1:18080",)
    assert scope.max_requests == 500
    assert scope.max_seconds == 300

    allowed, reason = scope_allows(scope, target)
    assert allowed, reason


def test_run_dry_run_prints_the_full_live_sequence() -> None:
    result = _shell("targets/dvwa/run.sh", "--dry-run")
    assert result.returncode == 0, result.stderr
    output = result.stdout
    expected = (
        "docker compose -f targets/dvwa/compose.yaml up -d",
        "sh targets/dvwa/setup.sh --url http://127.0.0.1:8080",
        "scope.md",
        "threat-model.md",
        "sak plan --suite web-blackbox",
        "--run-dir",
        "--allow-missing-requires",
        "--step nuclei --execute",
        "--step playwright --execute",
        "sak findings import",
        "sak report",
        "no container was started and no request was sent",
    )
    for fragment in expected:
        assert fragment in output, f"dry run is missing {fragment!r}"
    assert output.index("--step playwright --execute") < output.index("--step nuclei --execute")
    assert "password=password" not in output.lower()


def test_run_dry_run_supports_the_mac_tunnel_path() -> None:
    result = _shell(
        "targets/dvwa/run.sh",
        "--dry-run",
        "--no-compose",
        "--url",
        "http://127.0.0.1:18080",
    )
    assert result.returncode == 0, result.stderr
    assert "skipped (--no-compose; use the Mac SSH tunnel)" in result.stdout
    assert "http://127.0.0.1:18080" in result.stdout
    assert "docker compose -f targets/dvwa/compose.yaml up -d" not in result.stdout


def test_run_refuses_a_non_loopback_target() -> None:
    result = _shell("targets/dvwa/run.sh", "--dry-run", "--url", "http://example.com:8080")
    assert result.returncode != 0
    assert "loopback-only" in result.stderr
    assert "example.com" in result.stderr


def test_setup_refuses_a_non_loopback_target() -> None:
    result = _shell("targets/dvwa/setup.sh", "--dry-run", "--url", "https://dvwa.example.com")
    assert result.returncode != 0
    assert "loopback-only" in result.stderr
    assert "dvwa.example.com" in result.stderr


def test_no_embedded_secrets() -> None:
    patterns = {
        "aws access key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "github token": re.compile(r"ghp_[A-Za-z0-9]{20,}"),
        "slack token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        "api key": re.compile(r"sk-[A-Za-z0-9]{20,}"),
        "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        "bearer token": re.compile(r"Authorization:\s*Bearer\s+\S+", re.IGNORECASE),
    }
    for path in sorted(DVWA.rglob("*")):
        if not path.is_file() or path.name == ".env":
            continue
        text = path.read_text(encoding="utf-8")
        for label, pattern in patterns.items():
            assert not pattern.search(text), f"{label} found in {path}"
        if path != ENV_EXAMPLE:
            assert "DVWA_PASSWORD=password" not in text

    setup_text = SETUP.read_text(encoding="utf-8")
    assert not re.search(r"echo[^\n]*\$PASSWORD", setup_text)
    assert not re.search(r"echo[^\n]*\$TOKEN", setup_text)
    assert "password=password" not in CHECKS.read_text(encoding="utf-8").lower()


def test_readme_and_docs_cover_both_paths_and_operations() -> None:
    required = (
        "kali",
        "wsl",
        "mac",
        "ssh -l",
        "legion-ts",
        "start",
        "stop",
        "reset",
        "test account",
        "security",
        "scope",
        "evidence",
        "cleanup",
        "live",
        "prerequisite",
        "--dry-run",
        "--no-compose",
        "dvwa_port",
        "vulnerables/web-dvwa",
        "nuclei",
        "playwright",
        "needs_validation",
    )
    for path in (README, DOCS):
        text = path.read_text(encoding="utf-8").lower()
        for term in required:
            assert term in text, f"{path} is missing {term!r}"

    assert "docs/targets/dvwa.md" in README.read_text(encoding="utf-8")
    assert "../../targets/dvwa/" in DOCS.read_text(encoding="utf-8")
