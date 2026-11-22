"""Offline tests for the Playwright adapter and its Node runner contract.

Every test uses the fixture scenario/result files under ``tests/fixtures/playwright`` or a fake
``node``/``npx`` executable. No browser is launched, no network request is made and nothing is
installed. The one test that executes the real runner uses its ``--check`` mode, which only reads
the scenario, and is skipped when Node.js is absent.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from sak import run as run_module

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "playwright"
RUN_FIXTURE = FIXTURES / "run"
SCENARIO = RUN_FIXTURE / "scenario.json"
RESULT = FIXTURES / "result.json"
ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalog"
RUNNER = ROOT / "adapters" / "playwright" / "runner.mjs"
NODE = shutil.which("node")


# --------------------------------------------------------------------------- helpers


def adapter():
    return run_module.load_adapter("playwright")


def fake_binary(bindir: Path, name: str, body: str) -> Path:
    bindir.mkdir(parents=True, exist_ok=True)
    path = bindir / name
    path.write_text(f"#!{sys.executable}\n{body}")
    path.chmod(0o755)
    return path


FAKE_NODE = """
import json, os, pathlib, sys
argv = sys.argv[1:]
if "--version" in argv:
    print("v99.9.9-fake")
    raise SystemExit(0)
if "-e" in argv:
    raise SystemExit(1 if os.environ.get("SAK_FAKE_MODULE") == "missing" else 0)

def option(flag):
    return argv[argv.index(flag) + 1] if flag in argv else None

if os.environ.get("SAK_FAKE_ARGS"):
    pathlib.Path(os.environ["SAK_FAKE_ARGS"]).write_text(json.dumps(argv))
if os.environ.get("SAK_FAKE_MARKER") and "--scenario" in argv:
    pathlib.Path(os.environ["SAK_FAKE_MARKER"]).write_text("ran")

out = option("--out")
if not out:
    print("fake node: no --out", file=sys.stderr)
    raise SystemExit(2)

mode = os.environ.get("SAK_FAKE_RESULT", "valid")
if mode == "none":
    raise SystemExit(0)
if mode == "malformed":
    pathlib.Path(out).write_text("not json at all")
    raise SystemExit(1)
if mode == "module-missing":
    payload = {
        "schema_version": "1",
        "ok": False,
        "error": "the playwright module is not importable from this Node environment",
        "steps": [],
    }
else:
    payload = json.loads(pathlib.Path(os.environ["SAK_FAKE_RESULT_PATH"]).read_text())
pathlib.Path(out).write_text(json.dumps(payload))
print(json.dumps({"ok": True, "steps": len(payload.get("steps", []))}))
"""

FAKE_NPX = """
raise SystemExit(0)
"""


def use_fake_toolchain(
    monkeypatch,
    tmp_path: Path,
    *,
    node: bool = True,
    npx: bool = True,
    browser: bool = True,
) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    if node:
        fake_binary(bindir, "node", FAKE_NODE)
    if npx:
        fake_binary(bindir, "npx", FAKE_NPX)
    monkeypatch.setenv("PATH", str(bindir))
    cache = tmp_path / "browsers"
    cache.mkdir(parents=True, exist_ok=True)
    if browser:
        (cache / "chromium-9999").mkdir()
    monkeypatch.setenv("SAK_PLAYWRIGHT_BROWSERS_PATH", str(cache))
    monkeypatch.setenv("SAK_FAKE_RESULT_PATH", str(RESULT))
    return bindir


def make_run_dir(tmp_path: Path) -> Path:
    run_dir = tmp_path / "run"
    shutil.copytree(RUN_FIXTURE, run_dir)
    return run_dir


def scenario_step(**overrides) -> dict:
    step = {
        "id": "playwright",
        "options": {"scenario": str(SCENARIO), "timeout_seconds": 30},
    }
    step["options"].update(overrides)
    return step


# --------------------------------------------------------------------------- interface


def test_adapter_exposes_the_documented_interface():
    module = adapter()
    for attribute in (
        "ADAPTER_ID",
        "NAME",
        "REQUIRES",
        "DESTINATION_POLICY",
        "LICENSE_NOTICE",
        "check",
        "build",
        "execute",
        "parse",
        "estimate_requests",
    ):
        assert hasattr(module, attribute), f"playwright is missing {attribute}"
    assert module.ADAPTER_ID == "playwright"
    assert module.DESTINATION_POLICY == "target"
    assert "Apache-2.0" in module.LICENSE_NOTICE
    assert "vendor" in module.LICENSE_NOTICE or "never" in module.LICENSE_NOTICE

    check = module.check()
    assert check["adapter"] == "playwright"
    assert set(check) >= {"available", "missing", "hints", "notes", "license_notice"}
    assert check["runner"] == str(RUNNER)


def test_check_reports_missing_node_npx_and_browser(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    monkeypatch.setenv("SAK_PLAYWRIGHT_BROWSERS_PATH", str(tmp_path / "browsers"))

    check = adapter().check()

    assert check["available"] is False
    assert "node" in check["missing"]
    assert "npx" in check["missing"]
    assert "chromium browser" in check["missing"]
    assert check["browser_found"] is False
    hints = " ".join(check["hints"])
    assert "npm install --global playwright" in hints
    assert "npx playwright install chromium" in hints


def test_check_reports_node_npx_runner_and_cached_chromium(monkeypatch, tmp_path):
    use_fake_toolchain(monkeypatch, tmp_path)

    check = adapter().check()

    assert check["available"] is True
    assert check["missing"] == []
    assert check["version"] == "v99.9.9-fake"
    assert check["module_found"] is True
    assert check["browser_found"] is True
    assert check["runner_found"] is True
    assert check["hints"] == []


def test_check_reports_a_missing_playwright_module(monkeypatch, tmp_path):
    use_fake_toolchain(monkeypatch, tmp_path)
    monkeypatch.setenv("SAK_FAKE_MODULE", "missing")

    check = adapter().check()

    assert check["available"] is False
    assert "playwright module" in check["missing"]
    assert any("NODE_PATH" in note for note in check["notes"])
    assert "npx playwright install chromium" in " ".join(check["hints"])


def test_check_never_starts_the_runner(monkeypatch, tmp_path):
    use_fake_toolchain(monkeypatch, tmp_path)
    marker = tmp_path / "node-ran"
    monkeypatch.setenv("SAK_FAKE_MARKER", str(marker))

    check = adapter().check()

    assert check["available"] is True
    assert not marker.exists()


# --------------------------------------------------------------------------- build / dry run


def test_build_dry_run_prints_the_runner_command_without_launching(monkeypatch, tmp_path):
    use_fake_toolchain(monkeypatch, tmp_path)
    marker = tmp_path / "node-ran"
    monkeypatch.setenv("SAK_FAKE_MARKER", str(marker))
    run_dir = make_run_dir(tmp_path)

    built = adapter().build(
        {"id": "playwright", "options": {"scenario": "scenario.json", "timeout_seconds": 30}},
        "http://localhost:8765",
        run_dir=run_dir,
    )

    command = built["command"]
    assert command[1] == str(RUNNER)
    assert command[command.index("--scenario") + 1] == str((run_dir / "scenario.json").resolve())
    assert command[command.index("--target") + 1] == "http://localhost:8765"
    assert command[command.index("--out") + 1] == str(run_dir / "logs" / "playwright-result.json")
    assert command[command.index("--timeout-seconds") + 1] == "30"
    assert command[command.index("--browser") + 1] == "chromium"
    assert "--headed" not in command
    assert built["requires_scope"] is True
    assert built["output_path"] == str(run_dir / "logs" / "playwright-result.json")
    assert any("PLAYWRIGHT_FIXTURE_PASSWORD" in note for note in built["notes"])
    assert "fixture" not in " ".join(command), "the dry run must not resolve environment placeholders"
    assert not marker.exists(), "a dry run must never start Node"


def test_build_dry_run_without_a_run_directory_uses_a_placeholder(tmp_path):
    built = adapter().build(
        scenario_step(),
        "http://localhost:8765",
        binary=str(tmp_path / "bin" / "node"),
    )
    assert built["output_path"] is None
    assert built["command"][built["command"].index("--out") + 1] == (
        "<run_dir>/logs/playwright-result.json"
    )


def test_build_requires_a_scenario_option():
    with pytest.raises(ValueError, match="options.scenario"):
        adapter().build({"id": "playwright", "options": {}}, "http://localhost:8765")


def test_build_rejects_a_missing_scenario_file(tmp_path):
    with pytest.raises(ValueError, match="scenario not found"):
        adapter().build(
            {"id": "playwright", "options": {"scenario": "absent.json"}},
            "http://localhost:8765",
            run_dir=tmp_path,
        )


def test_build_rejects_an_unknown_scenario_action():
    with pytest.raises(ValueError, match="unknown action 'upload'"):
        adapter().build(
            {"id": "playwright", "options": {"scenario": str(FIXTURES / "scenario-bad-action.json")}},
            "http://localhost:8765",
        )


def test_build_rejects_a_scenario_without_steps(tmp_path):
    scenario = tmp_path / "empty.json"
    scenario.write_text(json.dumps({"steps": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="non-empty steps"):
        adapter().build(
            {"id": "playwright", "options": {"scenario": str(scenario)}}, "http://localhost:8765"
        )


def test_estimate_requests_counts_the_initial_load_and_network_actions():
    module = adapter()
    assert module.estimate_requests(scenario_step(), 60) == 6
    assert module.estimate_requests(scenario_step(), 0) == 0
    assert module.estimate_requests({"options": {"scenario": "missing.json"}}, 60) == 1


# --------------------------------------------------------------------------- parse


def test_parse_normalizes_observations_to_needs_validation_candidates():
    findings = adapter().parse(RESULT.read_text(encoding="utf-8"))

    assert len(findings) == 2
    assert all(item["status"] == "needs_validation" for item in findings)
    assert all(item["source"] == "playwright" for item in findings)
    assert all(item["id"].startswith("playwright:") for item in findings)

    http_error, expectation = findings
    assert http_error["id"].startswith("playwright:1:http_error")
    assert http_error["severity"] == "low"
    assert http_error["target"] == "http://localhost:8765/missing"
    assert http_error["evidence"]["kind"] == "http_error"
    assert http_error["evidence"]["observed"] == 404

    assert expectation["severity"] == "medium"
    assert expectation["evidence"]["kind"] == "expectation_failed"
    assert expectation["evidence"]["step"] == 5
    assert expectation["evidence"]["expected"] == "Welcome"
    assert expectation["evidence"]["screenshot"].endswith("after-login.png")


def test_parse_never_propagates_cookie_names_or_values():
    payload = {
        "target": "http://localhost:8765",
        "steps": [],
        "cookies": [{"name": "PHPSESSID", "value": "fixture-cookie-value"}],
        "observations": [
            {
                "kind": "expectation_failed",
                "severity": "medium",
                "title": "Expectation failed: expect_url",
                "step": 1,
                "url": "http://localhost:8765/login",
                "expected": "/account",
                "observed": "/login",
            }
        ],
    }

    findings = adapter().parse(json.dumps(payload))
    rendered = json.dumps(findings)

    assert len(findings) == 1
    assert "fixture-cookie-value" not in rendered
    assert "PHPSESSID" not in rendered


def test_parse_rejects_malformed_and_incomplete_runner_output():
    module = adapter()
    with pytest.raises(ValueError, match="invalid playwright runner JSON"):
        module.parse((FIXTURES / "result-malformed.json").read_text(encoding="utf-8"))
    with pytest.raises(ValueError, match="needs a steps list"):
        module.parse('{"ok": false}')
    with pytest.raises(ValueError, match="runner error"):
        module.parse(json.dumps({"steps": [], "error": "the playwright module is not importable"}))
    with pytest.raises(ValueError, match="observations must be a list"):
        module.parse(json.dumps({"steps": [], "observations": {}}))


# --------------------------------------------------------------------------- execute


def test_execute_with_a_fake_runner_parses_the_result(monkeypatch, tmp_path):
    use_fake_toolchain(monkeypatch, tmp_path)
    args_log = tmp_path / "args.json"
    monkeypatch.setenv("SAK_FAKE_ARGS", str(args_log))
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    result = adapter().execute(
        {"id": "playwright", "options": {"scenario": str(SCENARIO), "timeout_seconds": 30}},
        "http://localhost:8765",
        run_dir=run_dir,
    )

    assert result.get("refused") is not True
    assert len(result["findings"]) == 2
    assert "parse_error" not in result
    assert Path(result["output_path"]).is_file()
    argv = json.loads(args_log.read_text())
    assert argv[argv.index("--scenario") + 1] == str(SCENARIO)
    assert argv[argv.index("--target") + 1] == "http://localhost:8765"


def test_execute_without_a_run_dir_uses_a_temporary_directory(monkeypatch, tmp_path):
    use_fake_toolchain(monkeypatch, tmp_path)

    result = adapter().execute(scenario_step(), "http://localhost:8765")

    assert len(result["findings"]) == 2
    assert result["output_path"] is None
    assert not (Path.cwd() / "<run_dir>").exists()


def test_execute_refuses_without_node(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    monkeypatch.setenv("SAK_PLAYWRIGHT_BROWSERS_PATH", str(tmp_path / "browsers"))

    result = adapter().execute(scenario_step(), "http://localhost:8765")

    assert result["refused"] is True
    assert "node is not installed" in result["reason"]
    assert result["hints"]


def test_execute_refuses_without_npx(monkeypatch, tmp_path):
    use_fake_toolchain(monkeypatch, tmp_path, npx=False)

    result = adapter().execute(scenario_step(), "http://localhost:8765")

    assert result["refused"] is True
    assert "npx is not installed" in result["reason"]


def test_execute_refuses_without_the_playwright_module(monkeypatch, tmp_path):
    use_fake_toolchain(monkeypatch, tmp_path)
    monkeypatch.setenv("SAK_FAKE_MODULE", "missing")

    result = adapter().execute(scenario_step(), "http://localhost:8765")

    assert result["refused"] is True
    assert "playwright module" in result["reason"]


def test_execute_refuses_without_a_cached_browser(monkeypatch, tmp_path):
    use_fake_toolchain(monkeypatch, tmp_path, browser=False)
    marker = tmp_path / "node-ran"
    monkeypatch.setenv("SAK_FAKE_MARKER", str(marker))

    result = adapter().execute(scenario_step(), "http://localhost:8765")

    assert result["refused"] is True
    assert "npx playwright install chromium" in result["reason"]
    assert not marker.exists()


def test_execute_refuses_without_the_runner(monkeypatch, tmp_path):
    use_fake_toolchain(monkeypatch, tmp_path)
    module = adapter()
    monkeypatch.setattr(module, "runner_path", lambda: tmp_path / "missing-runner.mjs")

    result = module.execute(scenario_step(), "http://localhost:8765")

    assert result["refused"] is True
    assert "runner not found" in result["reason"]


def test_execute_reports_a_missing_result_document(monkeypatch, tmp_path):
    use_fake_toolchain(monkeypatch, tmp_path)
    monkeypatch.setenv("SAK_FAKE_RESULT", "none")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    result = adapter().execute(scenario_step(), "http://localhost:8765", run_dir=run_dir)

    assert result["findings"] == []
    assert "did not write a result document" in result["parse_error"]


def test_execute_reports_malformed_runner_output(monkeypatch, tmp_path):
    use_fake_toolchain(monkeypatch, tmp_path)
    monkeypatch.setenv("SAK_FAKE_RESULT", "malformed")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    result = adapter().execute(scenario_step(), "http://localhost:8765", run_dir=run_dir)

    assert result["findings"] == []
    assert "invalid playwright runner JSON" in result["parse_error"]


# --------------------------------------------------------------------------- run integration


def test_run_step_dry_run_reports_the_target_policy(monkeypatch, tmp_path):
    use_fake_toolchain(monkeypatch, tmp_path)
    marker = tmp_path / "node-ran"
    monkeypatch.setenv("SAK_FAKE_MARKER", str(marker))
    run_dir = make_run_dir(tmp_path)

    report = run_module.run_step(run_dir, "playwright", execute=False, catalog_path=CATALOG)

    assert report["ok"] is True
    assert report["dry_run"] is True
    assert report["destination"] == {"policy": "target", "enforceable": True}
    assert report["scope"]["allowed"] is True
    assert str((run_dir / "scenario.json").resolve()) in report["command"]
    assert report["budget"]["estimated_requests"] == 6
    assert report["findings"] == []
    assert not marker.exists()


def test_run_step_execute_writes_candidates_and_artifacts(monkeypatch, tmp_path):
    use_fake_toolchain(monkeypatch, tmp_path)
    marker = tmp_path / "node-ran"
    monkeypatch.setenv("SAK_FAKE_MARKER", str(marker))
    run_dir = make_run_dir(tmp_path)

    report = run_module.run_step(run_dir, "playwright", execute=True, catalog_path=CATALOG)

    assert report["ok"] is True
    assert report["returncode"] == 0
    assert len(report["findings"]) == 2
    assert all(item["status"] == "needs_validation" for item in report["findings"])
    assert marker.exists(), "execute should have started the runner"
    assert Path(report["artifacts"]["findings"]).is_file()
    log = Path(report["artifacts"]["log"]).read_text(encoding="utf-8")
    assert "destination_policy: target" in log
    assert json.loads((run_dir / "budget.json").read_text())["steps"][0]["step"] == "playwright"


def test_run_step_execute_refuses_a_target_outside_scope(monkeypatch, tmp_path):
    use_fake_toolchain(monkeypatch, tmp_path)
    marker = tmp_path / "node-ran"
    monkeypatch.setenv("SAK_FAKE_MARKER", str(marker))
    run_dir = make_run_dir(tmp_path)
    (run_dir / "scope.md").write_text("# Scope\n\n## Allowed hosts\n- localhost:9999\n", encoding="utf-8")

    report = run_module.run_step(run_dir, "playwright", execute=True, catalog_path=CATALOG)

    assert report["refused"] is True
    assert "scope refusal" in report["reason"]
    assert not marker.exists()
    assert not (run_dir / "logs").exists()


def test_run_step_execute_refuses_a_missing_browser(monkeypatch, tmp_path):
    use_fake_toolchain(monkeypatch, tmp_path, browser=False)
    marker = tmp_path / "node-ran"
    monkeypatch.setenv("SAK_FAKE_MARKER", str(marker))
    run_dir = make_run_dir(tmp_path)

    report = run_module.run_step(run_dir, "playwright", execute=True, catalog_path=CATALOG)

    assert report["refused"] is True
    assert "chromium browser" in report["reason"]
    assert not marker.exists()


# --------------------------------------------------------------------------- catalog


def test_catalog_card_points_at_the_adapter_and_scenario_contract():
    from sak import catalog as catalog_module

    catalog = catalog_module.load_catalog(CATALOG)
    card = catalog.find("playwright")

    assert card.type == "tool"
    assert card.status == "verified"
    assert card.data.get("adapter") == "playwright"
    assert card.data.get("requires") == ["node", "npx"]
    assert card.data["install"]["command"] == "npm install --global playwright"
    assert "npx playwright install chromium" in card.data["install"]["notes"]
    assert "options.scenario" in card.data["run"]["notes"]
    assert card.data["safety"]["destructive"] is False
    assert card.data["outputs"]
    assert "adapters/playwright.py" in card.data["notes"]


# --------------------------------------------------------------------------- runner contract


def test_build_keeps_placeholders_out_of_the_command_line(monkeypatch, tmp_path):
    use_fake_toolchain(monkeypatch, tmp_path)
    built = adapter().build(scenario_step(), "http://localhost:8765")
    display = built["display"]

    assert "${PLAYWRIGHT_FIXTURE_PASSWORD}" not in display
    assert "fixture-password-not-real" not in display
    assert "${PLAYWRIGHT_FIXTURE_USER}" in SCENARIO.read_text(encoding="utf-8")
    assert built["env_names"] == ["PLAYWRIGHT_FIXTURE_USER", "PLAYWRIGHT_FIXTURE_PASSWORD"]


@pytest.mark.skipif(NODE is None, reason="Node.js is required for the runner --check mode")
def test_runner_check_substitutes_named_variables_without_a_browser(tmp_path):
    env = dict(os.environ)
    env.update(
        {
            "PLAYWRIGHT_FIXTURE_USER": "fixture-user",
            "PLAYWRIGHT_FIXTURE_PASSWORD": "fixture-password-not-real",
        }
    )

    completed = subprocess.run(
        [NODE, str(RUNNER), "--scenario", str(SCENARIO), "--check"],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    summary = json.loads(completed.stdout)
    assert summary["ok"] is True
    assert summary["env_names"] == ["PLAYWRIGHT_FIXTURE_USER", "PLAYWRIGHT_FIXTURE_PASSWORD"]
    assert summary["missing_env"] == []
    assert summary["steps"] == 10
    assert "fixture-password-not-real" not in completed.stdout
    assert not (tmp_path / "playwright-result.json").exists()


@pytest.mark.skipif(NODE is None, reason="Node.js is required for the runner --check mode")
def test_runner_check_reports_a_missing_variable_without_its_value():
    env = dict(os.environ)
    for name in ("PLAYWRIGHT_FIXTURE_USER", "PLAYWRIGHT_FIXTURE_PASSWORD"):
        env.pop(name, None)

    completed = subprocess.run(
        [NODE, str(RUNNER), "--scenario", str(SCENARIO), "--check"],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 2
    summary = json.loads(completed.stdout)
    assert summary["ok"] is False
    assert "PLAYWRIGHT_FIXTURE_PASSWORD" in summary["missing_env"]


@pytest.mark.skipif(NODE is None, reason="Node.js is required to validate the runner")
def test_runner_check_rejects_an_unknown_action(tmp_path):
    completed = subprocess.run(
        [NODE, str(RUNNER), "--scenario", str(FIXTURES / "scenario-bad-action.json"), "--check"],
        capture_output=True,
        text=True,
        env=dict(os.environ),
        timeout=30,
        check=False,
    )

    assert completed.returncode == 2
    assert "unknown action" in completed.stderr
