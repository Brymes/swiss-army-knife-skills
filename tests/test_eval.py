"""Tests for the deterministic fixture evaluation.

The full 28-probe run is exercised by `python3 eval/run_fixture.py` in the
integration pass. These tests keep the fast contracts: the 14-issue table,
offline positive/negative/error combinations, artifact validation, live agent
lifecycle and port/reset/masking regressions. Every network call is loopback to
the local fixture; every credential is synthetic.
"""

from __future__ import annotations

import json
import os
import shlex
import socket
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

import pytest

from sak import catalog as catalog_module
from sak import eval as eval_module
from sak import findings as findings_module
from sak.__main__ import main as cli_main

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "vuln_app" / "run.py"


class FakeFixture:
    """In-memory context compatible with the probe runner; sends no traffic."""

    def __init__(self) -> None:
        self.base_url = "http://127.0.0.1:9"
        self.resets = 0

    def __enter__(self) -> "FakeFixture":
        return self

    def __exit__(self, *exc_info: object) -> bool:
        return False

    def reset(self) -> None:
        self.resets += 1


def synthetic_issue(
    positive,
    safe,
    *,
    number: int = 1,
    card: str = "VIBE-01",
) -> dict[str, object]:
    return {
        "number": number,
        "card": card,
        "title": f"Synthetic issue {number}",
        "severity": "high",
        "entrypoint": "GET /synthetic",
        "root_cause": f"synthetic-root-cause-{number}",
        "principal": "tester",
        "resource": "synthetic resource",
        "safe_entrypoint": "GET /synthetic/safe",
        "positive": positive,
        "safe": safe,
    }


def fake_evaluate(tmp_path: Path, issue: dict[str, object]) -> dict:
    return eval_module.evaluate(
        fixture_script=FIXTURE,
        run_dir=tmp_path,
        run_id="fake-eval",
        port=None,
        only=None,
        write_artifacts=True,
        _issues=[issue],
        _fixture_factory=lambda *_: FakeFixture(),
    )


def test_issue_table_covers_all_fourteen_with_controls() -> None:
    issues = eval_module.ISSUES
    assert len(issues) == 14
    assert [issue["number"] for issue in issues] == list(range(1, 15))
    cards = [issue["card"] for issue in issues]
    assert len(set(cards)) == 14
    for issue in issues:
        assert callable(issue["positive"])
        assert callable(issue["safe"])
        assert issue["entrypoint"]
        assert issue["safe_entrypoint"]
        assert issue["root_cause"]
        assert issue["title"]


def test_issue_cards_exist_in_the_valid_catalog() -> None:
    loaded = catalog_module.load_catalog(ROOT / "catalog")
    assert catalog_module.validate_catalog(loaded) == []
    prompts = loaded.ids("prompt")
    for issue in eval_module.ISSUES:
        assert issue["card"] in prompts, issue["card"]


def test_single_issue_run_writes_valid_artifacts(tmp_path: Path) -> None:
    document = eval_module.evaluate(
        fixture_script=FIXTURE,
        run_dir=tmp_path,
        run_id="pytest-eval",
        port=None,
        only=["VIBE-10"],
        write_artifacts=True,
    )
    metrics = document["metrics"]
    assert metrics["recall"] == {"detected": 1, "total": 1, "value": 1.0}
    assert metrics["precision"]["false_positives"] == 0
    assert metrics["precision"]["control_errors"] == 0
    assert metrics["probe_errors"] == 0
    assert metrics["precision"]["value"] == 1.0
    assert metrics["coverage"] == {"executed_probes": 2, "planned_probes": 2, "value": 1.0}
    assert metrics["cost_usd"] == 0.0
    assert metrics["duplicates"]["duplicate_fingerprints"] == 0

    findings = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    ledger = json.loads((tmp_path / "coverage-ledger.json").read_text(encoding="utf-8"))
    metadata = json.loads((tmp_path / "run-metadata.json").read_text(encoding="utf-8"))
    assert findings_module.validate_document(findings, base_dir=tmp_path) == []
    assert findings_module.validate_ledger(ledger, base_dir=tmp_path, check_files=True) == []
    assert findings_module.validate_run_metadata(metadata) == []
    assert findings["findings"][0]["status"] == "confirmed"
    assert findings["findings"][0]["evidence"][0]["path"].startswith("evidence/")
    assert (tmp_path / "evidence").is_dir()
    assert (tmp_path / "logs" / "fixture.log").is_file()


def test_healthy_positive_and_clean_control_pass(tmp_path: Path) -> None:
    issue = synthetic_issue(lambda base: (True, "vulnerable observed"), lambda base: (True, "control clean"))
    document = fake_evaluate(tmp_path, issue)
    assert document["metrics"]["recall"]["detected"] == 1
    assert document["metrics"]["precision"]["false_positives"] == 0
    assert document["metrics"]["precision"]["control_errors"] == 0
    assert document["metrics"]["probe_errors"] == 0
    assert document["metrics"]["coverage"]["value"] == 1.0
    assert eval_module._threshold(document, 1)["threshold"]["passed"] is True


def test_failed_control_fails_the_threshold_even_when_positive_detects(tmp_path: Path) -> None:
    issue = synthetic_issue(lambda base: (True, "vulnerable observed"), lambda base: (False, "safe endpoint leaked"))
    document = fake_evaluate(tmp_path, issue)
    assert document["probes"][0]["negative"]["executed"] is True
    assert document["probes"][0]["negative"]["clean"] is False
    assert document["metrics"]["precision"]["true_positives"] == 1
    assert document["metrics"]["precision"]["false_positives"] == 1
    assert document["metrics"]["precision"]["value"] == 0.5
    assert document["metrics"]["precision"]["control_errors"] == 0
    assert eval_module._threshold(document, 1)["threshold"]["passed"] is False

    findings = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    statuses = sorted(item["status"] for item in findings["findings"])
    assert statuses == ["confirmed", "needs_validation"]
    assert findings_module.validate_document(findings, base_dir=tmp_path) == []


def test_positive_probe_error_is_unresolved_and_uncovered(tmp_path: Path) -> None:
    def boom(base: str):
        raise RuntimeError("boom --api-key sk-test-detect-123456")

    issue = synthetic_issue(boom, lambda base: (True, "control clean"))
    document = fake_evaluate(tmp_path, issue)
    assert document["probes"][0]["positive"]["executed"] is False
    assert document["probes"][0]["positive"]["detected"] is False
    assert "sk-test-detect-123456" not in json.dumps(document)
    assert document["metrics"]["probe_errors"] == 1
    assert document["metrics"]["precision"]["control_errors"] == 0
    assert document["metrics"]["coverage"]["value"] == 0.5
    assert eval_module._threshold(document, 1)["threshold"]["passed"] is False

    ledger = json.loads((tmp_path / "coverage-ledger.json").read_text(encoding="utf-8"))
    boundary = ledger["boundaries"][0]
    assert boundary["status"] == "uncovered"
    assert "did not execute" in boundary["gap"]
    assert boundary["probes"][0]["executed"] is False
    assert findings_module.validate_ledger(ledger, base_dir=tmp_path, check_files=True) == []

    evidence = (tmp_path / "evidence" / "E-VIBE-01-positive.txt").read_text(encoding="utf-8")
    assert "sk-test-detect-123456" not in evidence
    assert "***" in evidence


def test_control_error_is_separate_from_a_false_detection(tmp_path: Path) -> None:
    def boom(base: str):
        raise RuntimeError("control failed with Authorization: Bearer synth-control-token-123")

    issue = synthetic_issue(lambda base: (True, "vulnerable observed"), boom)
    document = fake_evaluate(tmp_path, issue)
    assert document["probes"][0]["negative"]["executed"] is False
    assert document["probes"][0]["negative"]["clean"] is None
    assert document["metrics"]["precision"]["false_positives"] == 0
    assert document["metrics"]["precision"]["control_errors"] == 1
    assert document["metrics"]["coverage"]["value"] == 0.5
    assert eval_module._threshold(document, 1)["threshold"]["passed"] is False

    ledger = json.loads((tmp_path / "coverage-ledger.json").read_text(encoding="utf-8"))
    assert ledger["boundaries"][0]["status"] == "covered"
    assert ledger["boundaries"][1]["status"] == "uncovered"
    assert "did not execute" in ledger["boundaries"][1]["gap"]
    assert findings_module.validate_ledger(ledger, base_dir=tmp_path, check_files=True) == []
    evidence = (tmp_path / "evidence" / "E-VIBE-01-safe.txt").read_text(encoding="utf-8")
    assert "synth-control-token-123" not in evidence


def test_threshold_requires_detection_and_no_false_positives() -> None:
    document = {
        "metrics": {
            "recall": {"detected": 9, "total": 14, "value": 9 / 14},
            "precision": {"false_positives": 0, "control_errors": 0},
            "probe_errors": 0,
        }
    }
    assert eval_module._threshold(document, 10)["threshold"]["passed"] is False
    document["metrics"]["recall"] = {"detected": 10, "total": 14, "value": 10 / 14}
    assert eval_module._threshold(document, 10)["threshold"]["passed"] is True
    document["metrics"]["precision"]["false_positives"] = 1
    assert eval_module._threshold(document, 10)["threshold"]["passed"] is False
    document["metrics"]["precision"]["false_positives"] = 0
    document["metrics"]["precision"]["control_errors"] = 1
    assert eval_module._threshold(document, 10)["threshold"]["passed"] is False
    document["metrics"]["precision"]["control_errors"] = 0
    document["metrics"]["probe_errors"] = 1
    assert eval_module._threshold(document, 10)["threshold"]["passed"] is False


def test_explicit_busy_port_is_refused_without_traffic() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        busy = int(listener.getsockname()[1])
        with pytest.raises(eval_module.EvalError, match="busy"):
            eval_module._free_port(busy)


def test_agent_eval_is_skipped_without_a_command(tmp_path: Path) -> None:
    result = eval_module.run_agent_eval(
        None,
        base_url="http://127.0.0.1:8765",
        run_dir=tmp_path,
        issues=list(eval_module.ISSUES),
    )
    assert result["status"] == "skipped"
    assert result["command"] is None
    assert result["cost_usd"] is None


def test_agent_eval_records_a_json_verdict(tmp_path: Path) -> None:
    command = (
        f"{shlex.quote(sys.executable)} -c "
        "\"import json; print(json.dumps(['VIBE-01', 'VIBE-02', 'unknown']))\""
    )
    result = eval_module.run_agent_eval(
        command,
        base_url="http://127.0.0.1:8765",
        run_dir=tmp_path,
        issues=list(eval_module.ISSUES),
    )
    assert result["status"] == "ran", result
    assert result["detected"] == ["VIBE-01", "VIBE-02"]
    assert result["detected_count"] == 2
    assert result["recall"] == round(2 / 14, 4)


def test_non_loopback_target_is_refused() -> None:
    with pytest.raises(eval_module.EvalError, match="non-loopback"):
        eval_module.Client("https://example.test")


def _stub_script(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    path.chmod(0o755)
    return path


def test_agent_runs_inside_a_live_reset_fixture_and_is_terminated(tmp_path: Path) -> None:
    stub = _stub_script(
        tmp_path / "live_agent.py",
        """
import http.client
import json
import sys
from urllib.parse import urlencode, urlparse

target = sys.argv[1]
parsed = urlparse(target)
health = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5)
health.request("GET", "/public/status")
response = health.getresponse()
body = response.read()
health.close()
if response.status != 200 or b"sak-t8" not in body:
    print("fixture-unreachable", file=sys.stderr)
    raise SystemExit(3)

login = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5)
payload = urlencode({"username": "bob", "password": "bob-pw"}).encode()
login.request("POST", "/login", body=payload, headers={"Content-Type": "application/x-www-form-urlencoded"})
response = login.getresponse()
response.read()
cookie = (response.getheader("Set-Cookie") or "").split(";", 1)[0]
login.close()
if response.status != 302 or not cookie:
    print("deterministic-reset-missing", file=sys.stderr)
    raise SystemExit(4)

check = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5)
check.request("GET", "/api/users/2", headers={"Cookie": cookie})
response = check.getresponse()
account = json.loads(response.read().decode())
check.close()
if response.status != 200 or account.get("username") != "bob":
    print("bob-was-not-reset", file=sys.stderr)
    raise SystemExit(5)
print(json.dumps(["VIBE-02"]))
""",
    )
    run_dir = tmp_path / "agent-run"
    code = cli_main(
        [
            "eval",
            "--run-dir",
            str(run_dir),
            "--run-id",
            "agent-live",
            "--only",
            "VIBE-02",
            "--artifacts",
            "--agent-command",
            f"{shlex.quote(sys.executable)} {shlex.quote(str(stub))} {{target}}",
        ]
    )
    assert code == 0
    document = json.loads((run_dir / "EVAL.json").read_text(encoding="utf-8"))
    agent = document["agent_eval"]
    assert agent["status"] == "ran", agent
    assert agent["returncode"] == 0
    assert agent["detected"] == ["VIBE-02"]
    assert agent["cost_usd"] is None
    # The fixture process must be gone after the CLI returns.
    port = urlparse(document["target"]).port
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=0.5).close()


def test_agent_command_and_stderr_are_masked_everywhere(tmp_path: Path, capsys) -> None:
    stub = _stub_script(
        tmp_path / "masked_agent.py",
        """
import http.client
import json
import sys
import urllib.parse

target = urllib.parse.urlparse(sys.argv[-1])
conn = http.client.HTTPConnection(target.hostname, target.port, timeout=5)
conn.request("GET", "/public/status")
response = conn.getresponse()
response.read()
conn.close()
if response.status != 200:
    raise SystemExit(3)
sys.stderr.write("Authorization: Bearer synth-agent-token-abc123\\n")
print(json.dumps(["VIBE-10"]))
""",
    )
    run_dir = tmp_path / "masked-run"
    command = (
        f"{shlex.quote(sys.executable)} {shlex.quote(str(stub))} "
        "--api-key sk-test-cli-abc123 {target}"
    )
    code = cli_main(
        [
            "eval",
            "--run-dir",
            str(run_dir),
            "--run-id",
            "masked",
            "--only",
            "VIBE-10",
            "--artifacts",
            "--agent-command",
            command,
            "--json",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0, captured.err
    assert "sk-test-cli-abc123" not in captured.out
    assert "synth-agent-token-abc123" not in captured.out
    assert "sk-test-cli-abc123" not in captured.err
    persisted = (run_dir / "EVAL.json").read_text(encoding="utf-8")
    markdown = (run_dir / "EVAL.md").read_text(encoding="utf-8")
    for text in (persisted, markdown):
        assert "sk-test-cli-abc123" not in text
        assert "synth-agent-token-abc123" not in text
    for evidence in (run_dir / "evidence").glob("*.txt"):
        body = evidence.read_text(encoding="utf-8")
        assert "sk-test-cli-abc123" not in body
        assert "synth-agent-token-abc123" not in body
    agent = json.loads(persisted)["agent_eval"]
    assert agent["status"] == "ran"
    assert "***" in agent["command"]
    assert agent["stderr_tail"] and "***" in agent["stderr_tail"][-1]


def test_placeholders_with_spaces_and_shell_characters_stay_one_argument(tmp_path: Path) -> None:
    stub = _stub_script(
        tmp_path / "path_agent.py",
        """
import http.client
import json
import os
import sys
import urllib.parse

target = urllib.parse.urlparse(sys.argv[1])
conn = http.client.HTTPConnection(target.hostname, target.port, timeout=5)
conn.request("GET", "/public/status")
response = conn.getresponse()
response.read()
conn.close()
if response.status != 200:
    raise SystemExit(3)
run_dir = sys.argv[2]
if not os.path.isdir(run_dir):
    print("run-dir-placeholder-broken", file=sys.stderr)
    raise SystemExit(4)
with open(os.path.join(run_dir, "agent-marker.txt"), "w", encoding="utf-8") as handle:
    handle.write(sys.argv[1])
print(json.dumps(["VIBE-10"]))
""",
    )
    weird = tmp_path / "run dir with 'quote' and ; semicolon"
    weird.mkdir()
    command = (
        f"{shlex.quote(sys.executable)} {shlex.quote(str(stub))} "
        "{target} {run_dir}"
    )
    code = cli_main(
        [
            "eval",
            "--run-dir",
            str(weird),
            "--run-id",
            "weird-path",
            "--only",
            "VIBE-10",
            "--agent-command",
            command,
        ]
    )
    assert code == 0
    marker = weird / "agent-marker.txt"
    assert marker.is_file()
    document = json.loads((weird / "EVAL.json").read_text(encoding="utf-8"))
    assert marker.read_text(encoding="utf-8") == document["target"]
    assert not (ROOT / "pwned").exists()


def test_agent_timeout_closes_the_fixture_and_keeps_metrics_separate(tmp_path: Path) -> None:
    run_dir = tmp_path / "timeout-run"
    command = f"{shlex.quote(sys.executable)} -c \"import time; time.sleep(60)\""
    code = cli_main(
        [
            "eval",
            "--run-dir",
            str(run_dir),
            "--run-id",
            "agent-timeout",
            "--only",
            "VIBE-10",
            "--agent-timeout",
            "1",
            "--agent-command",
            command,
        ]
    )
    assert code == 0
    document = json.loads((run_dir / "EVAL.json").read_text(encoding="utf-8"))
    assert document["threshold"]["passed"] is True
    agent = document["agent_eval"]
    assert agent["status"] == "failed"
    assert "exceeded 1s" in agent["reason"]
    port = urlparse(document["target"]).port
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=0.5).close()


def test_fixture_startup_failure_is_cleaned_up(tmp_path: Path) -> None:
    bad_fixture = _stub_script(
        tmp_path / "bad_fixture.py",
        """
import sys
if "--reset" in sys.argv:
    raise SystemExit(0)
sys.stderr.write("startup boom\\n")
raise SystemExit(7)
""",
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    with pytest.raises(eval_module.EvalError, match="exited during startup"):
        eval_module.evaluate(
            fixture_script=bad_fixture,
            run_dir=tmp_path / "bad-run",
            run_id="bad-start",
            port=port,
            only=["VIBE-10"],
            write_artifacts=False,
        )
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=0.5).close()


def test_demo_keeps_one_target_when_the_default_port_is_busy(tmp_path: Path) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind(("127.0.0.1", 8765))
        listener.listen(1)
    except OSError:
        listener.close()
        pytest.skip("127.0.0.1:8765 is not available for the occupied-port regression")

    run_dir = tmp_path / "demo"
    env = os.environ.copy()
    env["UV_OFFLINE"] = "1"
    try:
        result = subprocess.run(
            ["sh", str(ROOT / "scripts" / "demo.sh"), str(run_dir)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=240,
            env=env,
        )
    finally:
        listener.close()
    assert result.returncode == 0, result.stdout + result.stderr

    metadata = json.loads((run_dir / "run-metadata.json").read_text(encoding="utf-8"))
    plan = json.loads((run_dir / "plan.json").read_text(encoding="utf-8"))
    findings = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    evaluation = json.loads((run_dir / "EVAL.json").read_text(encoding="utf-8"))
    target = metadata["target"]["base_url"]
    assert target != "http://127.0.0.1:8765"
    assert plan["target"] == target
    assert findings["target"] == target
    assert evaluation["target"] == target
    assert target in (run_dir / "scope.md").read_text(encoding="utf-8")
    report = (run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert target in report
    # The demo's own eval must have covered the same target without a stray probe.
    assert evaluation["metrics"]["precision"]["false_positives"] == 0
    assert evaluation["threshold"]["passed"] is True
