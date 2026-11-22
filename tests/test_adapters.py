"""Offline adapter and ``sak run`` tests.

Every test uses the fake fixtures in ``tests/fixtures/adapters`` or a generated fake
binary. No live target is contacted, no template update runs and no package is installed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

from sak import run as run_module
from sak import util

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "adapters"
ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalog"
ADAPTERS = ("nuclei", "blackbird", "webseek")


# --------------------------------------------------------------------------- helpers


def adapter(name: str):
    return run_module.load_adapter(name)


def fake_binary(bindir: Path, name: str, body: str) -> Path:
    bindir.mkdir(parents=True, exist_ok=True)
    path = bindir / name
    path.write_text(f"#!{sys.executable}\n{body}")
    path.chmod(0o755)
    return path


FAKE_NUCLEI = """
import json, os, pathlib, sys
args = sys.argv[1:]
if "-version" in args:
    print("nuclei v9.9.9-fake")
    raise SystemExit(0)
marker = os.environ.get("SAK_FAKE_MARKER")
if marker:
    pathlib.Path(marker).write_text("ran")
token = os.environ.get("SAK_TEST_TOKEN", "")
query = "?q=1&api_key=" + token if token else "?q=1"
record = {
    "template-id": "fixture-sqli",
    "info": {"name": "Fixture SQL injection", "severity": "high", "tags": ["sqli"]},
    "type": "http",
    "host": "localhost:8765",
    "matched-at": "http://localhost:8765/search" + query,
    "matcher-name": "error",
    "extracted-results": ["token=" + token] if token else [],
}
print(json.dumps(record))
if token:
    print("Authorization: Bearer " + token, file=sys.stderr)
"""

FAKE_NPX = """
import json, os, pathlib, sys
marker = os.environ.get("SAK_FAKE_MARKER")
if marker:
    pathlib.Path(marker).write_text("ran")
data = {
    "provider": "fixture-provider",
    "results": [
        {"title": "Fixture research result", "url": "https://example.test/report", "snippet": "offline"},
        {"title": "Second fixture result", "url": "https://example.test/second", "snippet": "offline"},
    ],
    "usage": {"requests": 2, "tokens": 400},
    "cost_usd": 0.002,
}
print(json.dumps(data))
print(os.environ.get("WEBSEEK_API_KEY", ""), file=sys.stderr)
"""

FAKE_BLACKBIRD = """
import csv, os, pathlib, sys
args = sys.argv[1:]
marker = os.environ.get("SAK_FAKE_MARKER")
if marker:
    pathlib.Path(marker).write_text("ran")
if "--csv" not in args:
    raise SystemExit("fake blackbird needs --csv")
out = pathlib.Path(args[args.index("--csv") + 1])
out.parent.mkdir(parents=True, exist_ok=True)
with out.open("w", newline="") as handle:
    writer = csv.writer(handle)
    writer.writerow(["Site", "URL", "Username", "Exists", "Metadata"])
    writer.writerow(["github", "https://github.com/fixtureuser", "fixtureuser", "yes", "profile"])
    writer.writerow(["gitlab", "https://gitlab.com/fixtureuser", "fixtureuser", "no", ""])
"""


def make_run_dir(tmp_path: Path, *, plan: bool = True, scope: bool = True, scope_text: str | None = None) -> Path:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    if plan:
        shutil.copy(FIXTURES / "plan.json", run_dir / "plan.json")
    if scope:
        text = scope_text if scope_text is not None else (FIXTURES / "scope.md").read_text(encoding="utf-8")
        (run_dir / "scope.md").write_text(text, encoding="utf-8")
    return run_dir


def retarget_plan(run_dir: Path, target: str) -> None:
    plan_path = run_dir / "plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["target"] = target
    plan_path.write_text(json.dumps(plan), encoding="utf-8")


def make_blackbird_checkout(tmp_path: Path) -> Path:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "blackbird.py").write_text(FAKE_BLACKBIRD, encoding="utf-8")
    venv_bin = checkout / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    os.symlink(sys.executable, venv_bin / "python")
    return checkout


# --------------------------------------------------------------------------- interface


def test_adapters_expose_the_documented_interface():
    readme = ROOT / "adapters" / "README.md"
    assert readme.is_file()
    for name in ADAPTERS:
        module = adapter(name)
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
        ):
            assert hasattr(module, attribute), f"{name} is missing {attribute}"
        assert module.ADAPTER_ID == name
        assert module.DESTINATION_POLICY in {"target", "external", "provider"}
        if module.DESTINATION_POLICY != "target":
            assert module.DESTINATION_REFUSAL
        check = module.check()
        assert check["adapter"] == name
        assert "available" in check and "missing" in check and "hints" in check
        assert "license_notice" in check


def test_destination_policies_are_declared():
    assert adapter("nuclei").DESTINATION_POLICY == "target"
    assert adapter("blackbird").DESTINATION_POLICY == "external"
    assert adapter("webseek").DESTINATION_POLICY == "provider"


def test_adapter_loader_rejects_unknown_names():
    with pytest.raises(util.SakError):
        run_module.load_adapter("../escape")
    with pytest.raises(util.SakError):
        run_module.load_adapter("does-not-exist")


# --------------------------------------------------------------------------- nuclei


def test_nuclei_check_reports_missing_binary_with_install_hints(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    check = adapter("nuclei").check()
    assert check["available"] is False
    assert check["missing"] == ["nuclei"]
    joined = " ".join(check["hints"])
    assert "brew install nuclei" in joined
    assert "go install" in joined


def test_nuclei_check_reads_a_local_version_without_network(monkeypatch, tmp_path):
    bindir = tmp_path / "bin"
    fake_binary(bindir, "nuclei", FAKE_NUCLEI)
    monkeypatch.setenv("PATH", str(bindir))
    check = adapter("nuclei").check()
    assert check["available"] is True
    assert check["version"].startswith("nuclei v9.9.9-fake")


def test_nuclei_dry_run_command_applies_controls():
    step = {
        "id": "nuclei",
        "options": {"severity": "high,critical", "rate_limit": 7, "timeout": 9, "retries": 2},
    }
    built = adapter("nuclei").build(step, "http://localhost:8765")
    command = built["command"]
    assert "-u" in command and "http://localhost:8765" in command
    assert command[command.index("-severity") + 1] == "high,critical"
    assert command[command.index("-rate-limit") + 1] == "7"
    assert command[command.index("-timeout") + 1] == "9"
    assert command[command.index("-retries") + 1] == "2"
    assert "-no-interactsh" in command
    assert "-disable-update-check" in command
    assert "-jsonl" in command
    assert "-silent" in command  # keep banners/INFO out of the JSONL parser stream
    assert "-o" not in command  # no raw capture file under the run directory
    assert "-headless" not in command
    assert built["requires_scope"] is True


def test_nuclei_interactsh_is_opt_in_only():
    module = adapter("nuclei")
    default = module.build({"id": "nuclei"}, "http://localhost:8765")["command"]
    opted_in = module.build(
        {"id": "nuclei", "options": {"interactsh": True}}, "http://localhost:8765"
    )["command"]
    assert "-no-interactsh" in default
    assert "-no-interactsh" not in opted_in


def test_nuclei_rejects_unknown_severity():
    with pytest.raises(ValueError):
        adapter("nuclei").build({"id": "nuclei", "options": {"severity": "critical,apocalyptic"}}, "http://localhost:8765")


def test_nuclei_accepts_an_existing_local_template_path(tmp_path):
    templates = tmp_path / "templates"
    templates.mkdir()
    command = adapter("nuclei").build(
        {"id": "nuclei", "options": {"templates": str(templates)}}, "http://localhost:8765"
    )["command"]
    assert command[command.index("-t") + 1] == str(templates)


def test_nuclei_rejects_remote_or_missing_template_paths(tmp_path):
    module = adapter("nuclei")
    with pytest.raises(ValueError, match="remote template"):
        module.build(
            {"id": "nuclei", "options": {"templates": "https://templates.example.test/http"}},
            "http://localhost:8765",
        )
    with pytest.raises(ValueError, match="does not exist"):
        module.build(
            {"id": "nuclei", "options": {"templates": str(tmp_path / "missing")}},
            "http://localhost:8765",
        )


def test_nuclei_parse_normalizes_jsonl():
    findings = adapter("nuclei").parse((FIXTURES / "nuclei.jsonl").read_text(encoding="utf-8"))
    assert len(findings) == 2
    first = findings[0]
    assert first["id"].startswith("nuclei:fixture-sqli")
    assert first["status"] == "needs_validation"
    assert first["source"] == "nuclei"
    assert first["severity"] == "high"
    assert first["target"] == "http://localhost:8765/search?q=1"
    assert first["evidence"]["template"] == "fixture-sqli"
    assert findings[1]["severity"] == "low"


def test_nuclei_parse_rejects_malformed_jsonl():
    with pytest.raises(ValueError, match="line 2"):
        adapter("nuclei").parse('{"template-id": "ok"}\nnot json\n')


def test_nuclei_execute_with_fake_binary_writes_sanitized_artifacts(monkeypatch, tmp_path):
    bindir = tmp_path / "bin"
    fake_binary(bindir, "nuclei", FAKE_NUCLEI)
    monkeypatch.setenv("PATH", str(bindir))
    run_dir = make_run_dir(tmp_path)

    report = run_module.run_step(run_dir, "nuclei", execute=True, catalog_path=CATALOG)

    assert report["ok"] is True
    assert report["returncode"] == 0
    assert len(report["findings"]) == 1
    assert report["findings"][0]["status"] == "needs_validation"
    assert report["destination"] == {"policy": "target", "enforceable": True}
    log = Path(report["artifacts"]["log"])
    findings_path = Path(report["artifacts"]["findings"])
    step_path = Path(report["artifacts"]["step"])
    assert log.is_file() and "-no-interactsh" in log.read_text(encoding="utf-8")
    assert json.loads(findings_path.read_text(encoding="utf-8"))[0]["source"] == "nuclei"
    assert json.loads(step_path.read_text(encoding="utf-8"))["findings"] == 1
    budget = json.loads((run_dir / "budget.json").read_text(encoding="utf-8"))
    assert budget["requests"] > 0
    assert budget["steps"][0]["step"] == "nuclei"
    assert not list((run_dir / "steps").glob("*-nuclei.jsonl")), "raw capture must not be retained"


# --------------------------------------------------------------------------- scope


def test_scope_parses_hosts_and_budget():
    scope = run_module.parse_scope_text((FIXTURES / "scope.md").read_text(encoding="utf-8"))
    assert scope.hosts == ("localhost:8765", "127.0.0.1:8765")
    assert scope.excluded == ()
    assert scope.errors == ()
    assert scope.max_requests == 500
    assert scope.max_seconds == 60
    assert scope.present is False  # parsed text alone is not a file
    assert run_module.scope_allows(scope, "http://localhost:8765/search") == (
        True,
        "localhost:8765 allowed by localhost:8765",
    )
    allowed, reason = run_module.scope_allows(scope, "https://localhost/login")
    assert allowed is False and "not in the scope.md allowlist" in reason


def test_scope_is_default_deny_and_needs_a_positive_heading():
    empty = run_module.parse_scope_text("")
    assert empty.hosts == ()
    assert run_module.scope_allows(empty, "http://localhost:8765")[0] is False

    unheaded = run_module.parse_scope_text("- localhost:8765\n")
    assert unheaded.hosts == ()
    assert run_module.scope_allows(unheaded, "http://localhost:8765")[0] is False

    host_only = run_module.parse_scope_text("## Allowed hosts\n- localhost\n")
    assert run_module.scope_allows(host_only, "https://localhost/")[0] is True
    assert run_module.scope_allows(host_only, "https://example.test/")[0] is False


def test_exclusions_deny_and_never_authorize():
    scope = run_module.parse_scope_text(
        "## Allowed hosts\n- 127.0.0.1:8765\n## Out of scope\n- 127.0.0.2:8765\n"
    )
    assert scope.hosts == ("127.0.0.1:8765",)
    assert scope.excluded == ("127.0.0.2:8765",)
    allowed, reason = run_module.scope_allows(scope, "http://127.0.0.2:8765/")
    assert allowed is False and "excluded" in reason

    both = run_module.parse_scope_text(
        "## Allowed hosts\n- 127.0.0.3:8765\n## Exclusions\n- 127.0.0.3:8765\n"
    )
    assert run_module.scope_allows(both, "http://127.0.0.3:8765/")[0] is False


def test_notes_and_unknown_sections_never_authorize():
    scope = run_module.parse_scope_text(
        "## Allowed hosts\n- 127.0.0.1:8765\n"
        "## Notes\n- 127.0.0.4:8765\n"
        "## Forbidden actions\n- 127.0.0.5:8765\n"
        "## Methodology\n- 127.0.0.6:8765\n"
    )
    assert scope.hosts == ("127.0.0.1:8765",)
    for host in ("127.0.0.4:8765", "127.0.0.5:8765", "127.0.0.6:8765"):
        assert run_module.scope_allows(scope, f"http://{host}/")[0] is False


T4_SCOPE_TEMPLATE = """# Authorization

## In scope

| Asset | Type | Allowed methods / actions | Notes |
|---|---|---|---|
| https://app.example.test | web | GET, HEAD, POST (test accounts only) | staging copy |
| /api/v1 | api | GET, POST | documented endpoints |
| github.com/org/repo@<sha> | source | read-only clone | reviewed revision |
| 127.0.0.1:8765 | fixture | all fixture routes | local lab only |

## Out of scope

- <third-party hosts, payment providers, shared auth, production data>
- Destructive actions, DoS/load tests, persistence, data exfiltration.
- Real user accounts or real personal data. Use accounts: <A>, <B>, <admin>.

## Accounts and credentials

| Label | Role | How provisioned | Secret location |
|---|---|---|---|
| A | normal user | fixture seed | environment variable, never in a file |

## Budget

- Portfolio caps: primary <3>, support <4>, fallback <3>, brute <1>.
"""


def test_scope_consumes_the_reviewed_in_scope_table_template():
    scope = run_module.parse_scope_text(T4_SCOPE_TEMPLATE)
    assert scope.errors == ()
    assert scope.hosts == ("app.example.test", "127.0.0.1:8765")
    assert run_module.scope_allows(scope, "https://app.example.test/login")[0] is True
    assert run_module.scope_allows(scope, "http://127.0.0.1:8765/")[0] is True
    assert run_module.scope_allows(scope, "https://third-party.example/")[0] is False
    # Path, repository and source rows are not host destinations and are not errors.
    assert scope.excluded == ()


def test_scope_table_in_an_unrelated_section_is_ignored():
    scope = run_module.parse_scope_text(
        "## Allowed hosts\n- 127.0.0.1:8765\n"
        "## Accounts\n\n| Asset | Type |\n|---|---|\n| 127.0.0.9:8765 | web |\n"
    )
    assert scope.hosts == ("127.0.0.1:8765",)
    assert run_module.scope_allows(scope, "http://127.0.0.9:8765/")[0] is False
    assert scope.errors == ()


def test_scope_table_still_rejects_an_invalid_host_entry():
    scope = run_module.parse_scope_text(
        "## Allowed hosts\n\n| Asset | Type |\n|---|---|\n| *.example.test | web |\n"
    )
    assert scope.errors
    assert run_module.scope_allows(scope, "https://app.example.test/")[0] is False


def test_invalid_host_or_port_syntax_is_an_error_not_a_broader_rule():
    for entry in ("localhost:99999", "localhost:0", "*.example.test", "10.0.0.0/8", "user@localhost:8765"):
        scope = run_module.parse_scope_text(f"## Allowed hosts\n- {entry}\n")
        assert scope.errors, entry
        assert run_module.scope_allows(scope, "http://localhost:8765/")[0] is False


def test_invalid_scope_entry_refuses_execution_before_the_adapter_runs(monkeypatch, tmp_path):
    bindir = tmp_path / "bin"
    fake_binary(bindir, "nuclei", FAKE_NUCLEI)
    monkeypatch.setenv("PATH", str(bindir))
    marker = tmp_path / "nuclei-ran"
    monkeypatch.setenv("SAK_FAKE_MARKER", str(marker))
    run_dir = make_run_dir(tmp_path, scope_text="# Scope\n\n## Allowed hosts\n- localhost:99999\n")

    report = run_module.run_step(run_dir, "nuclei", execute=True, catalog_path=CATALOG)

    assert report["refused"] is True
    assert "invalid entries" in report["reason"]
    assert not marker.exists()
    assert not (run_dir / "logs").exists()


# --------------------------------------------------------------------------- gates


def test_execute_refuses_a_host_outside_the_allowlist(monkeypatch, tmp_path):
    bindir = tmp_path / "bin"
    fake_binary(bindir, "nuclei", FAKE_NUCLEI)
    monkeypatch.setenv("PATH", str(bindir))
    marker = tmp_path / "nuclei-ran"
    monkeypatch.setenv("SAK_FAKE_MARKER", str(marker))
    run_dir = make_run_dir(
        tmp_path,
        scope_text="# Scope\n\n## Allowed hosts\n- localhost:9999\n",
    )

    report = run_module.run_step(run_dir, "nuclei", execute=True, catalog_path=CATALOG)

    assert report["ok"] is False
    assert report["refused"] is True
    assert "scope refusal" in report["reason"]
    assert not marker.exists()
    assert not (run_dir / "logs").exists()
    assert not (run_dir / "steps").exists()


def test_execute_refuses_without_a_scope_file(monkeypatch, tmp_path):
    bindir = tmp_path / "bin"
    fake_binary(bindir, "nuclei", FAKE_NUCLEI)
    monkeypatch.setenv("PATH", str(bindir))
    run_dir = make_run_dir(tmp_path, scope=False)

    report = run_module.run_step(run_dir, "nuclei", execute=True, catalog_path=CATALOG)

    assert report["refused"] is True
    assert "scope.md" in report["reason"]


def test_execute_refuses_without_a_plan(monkeypatch, tmp_path):
    bindir = tmp_path / "bin"
    fake_binary(bindir, "nuclei", FAKE_NUCLEI)
    monkeypatch.setenv("PATH", str(bindir))
    run_dir = make_run_dir(tmp_path, plan=False)

    report = run_module.run_step(run_dir, "nuclei", execute=True, catalog_path=CATALOG)

    assert report["refused"] is True
    assert "plan.json" in report["reason"]


def test_execute_refuses_a_missing_tool_with_hints(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    run_dir = make_run_dir(tmp_path)

    report = run_module.run_step(run_dir, "nuclei", execute=True, catalog_path=CATALOG)

    assert report["refused"] is True
    assert "missing tool" in report["reason"]
    assert any("brew install nuclei" in hint for hint in report["hints"])
    assert any("missing tool" in warning for warning in report["warnings"])


def test_dry_run_warns_about_a_missing_tool_but_still_prints_the_command(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    run_dir = make_run_dir(tmp_path)

    report = run_module.run_step(run_dir, "nuclei", execute=False, catalog_path=CATALOG)

    assert report["ok"] is True
    assert report["dry_run"] is True
    assert report["tool"]["available"] is False
    assert any("missing tool" in warning for warning in report["warnings"])
    assert "-no-interactsh" in report["command"]


def test_budget_clips_the_wall_clock_to_the_request_cap(monkeypatch, tmp_path):
    bindir = tmp_path / "bin"
    fake_binary(bindir, "nuclei", FAKE_NUCLEI)
    monkeypatch.setenv("PATH", str(bindir))
    run_dir = make_run_dir(
        tmp_path,
        scope_text="# Scope\n\n## Allowed hosts\n- localhost:8765\n\n## Budget\n- max_requests: 10\n- max_seconds: 60\n",
    )

    report = run_module.run_step(run_dir, "nuclei", execute=False, catalog_path=CATALOG)

    budget = report["budget"]
    assert budget["max_requests"] == 10
    assert budget["effective_timeout_seconds"] == 2
    assert budget["estimated_requests"] == 10
    assert budget["exceeded"] is False


def test_budget_refuses_when_no_requests_remain(monkeypatch, tmp_path):
    bindir = tmp_path / "bin"
    fake_binary(bindir, "nuclei", FAKE_NUCLEI)
    monkeypatch.setenv("PATH", str(bindir))
    run_dir = make_run_dir(
        tmp_path,
        scope_text="# Scope\n\n## Allowed hosts\n- localhost:8765\n\n## Budget\n- max_requests: 0\n",
    )

    report = run_module.run_step(run_dir, "nuclei", execute=True, catalog_path=CATALOG)

    assert report["refused"] is True
    assert "budget refusal" in report["reason"]


def test_unknown_step_or_unplanned_step_raises(tmp_path):
    run_dir = make_run_dir(tmp_path)
    with pytest.raises(util.SakError, match="not a candidate"):
        run_module.run_step(run_dir, "not-in-plan", execute=False, catalog_path=CATALOG)


# --------------------------------------------------------------------------- destination policy


def test_blackbird_execute_is_refused_even_with_a_checkout(monkeypatch, tmp_path):
    checkout = make_blackbird_checkout(tmp_path)
    monkeypatch.setenv("SAK_BLACKBIRD_DIR", str(checkout))
    marker = tmp_path / "blackbird-ran"
    monkeypatch.setenv("SAK_FAKE_MARKER", str(marker))
    run_dir = make_run_dir(tmp_path)

    report = run_module.run_step(run_dir, "blackbird", execute=True, catalog_path=CATALOG)

    assert report["refused"] is True
    assert report["destination"] == {"policy": "external", "enforceable": False}
    assert "scope.md cannot authorize" in report["reason"]
    assert not marker.exists()
    assert not (run_dir / "findings").exists()


def test_webseek_execute_is_refused_even_with_a_key(monkeypatch, tmp_path):
    bindir = tmp_path / "bin"
    fake_binary(bindir, "npx", FAKE_NPX)
    monkeypatch.setenv("PATH", str(bindir))
    monkeypatch.setenv("WEBSEEK_API_KEY", "fixture-key-not-real")
    marker = tmp_path / "npx-ran"
    monkeypatch.setenv("SAK_FAKE_MARKER", str(marker))
    run_dir = make_run_dir(tmp_path)

    report = run_module.run_step(run_dir, "webseek", execute=True, catalog_path=CATALOG)

    assert report["refused"] is True
    assert report["destination"] == {"policy": "provider", "enforceable": False}
    assert "scope.md cannot authorize" in report["reason"]
    assert not marker.exists()
    assert not (run_dir / "findings").exists()


def test_dry_run_reports_the_destination_policy(monkeypatch, tmp_path):
    run_dir = make_run_dir(tmp_path)
    report = run_module.run_step(run_dir, "webseek", execute=False, catalog_path=CATALOG)
    assert report["ok"] is True
    assert report["destination"]["enforceable"] is False
    assert any("destination policy" in warning for warning in report["warnings"])


# --------------------------------------------------------------------------- blackbird


def test_blackbird_check_refuses_without_checkout(monkeypatch, tmp_path):
    monkeypatch.setenv("SAK_BLACKBIRD_DIR", str(tmp_path / "absent"))
    monkeypatch.delenv("SAK_BLACKBIRD_PYTHON", raising=False)
    check = adapter("blackbird").check()
    assert check["available"] is False
    assert "blackbird checkout" in check["missing"]
    assert "GPL-3.0" in check["license_notice"]
    assert "CC BY-NC-SA" in check["license_notice"]


def test_blackbird_adapter_execute_refuses_without_checkout(monkeypatch, tmp_path):
    monkeypatch.setenv("SAK_BLACKBIRD_DIR", str(tmp_path / "absent"))
    monkeypatch.delenv("SAK_BLACKBIRD_PYTHON", raising=False)
    result = adapter("blackbird").execute({"id": "blackbird", "options": {"username": "fixtureuser"}}, "http://localhost:8765")
    assert result["refused"] is True
    assert "checkout not found" in result["reason"]
    assert any("git clone" in hint for hint in result["hints"])


def test_blackbird_parse_normalizes_csv():
    findings = adapter("blackbird").parse((FIXTURES / "blackbird.csv").read_text(encoding="utf-8"))
    assert len(findings) == 2  # the "no" row is not a candidate
    assert findings[0]["id"].startswith("blackbird:github")
    assert findings[0]["target"] == "https://github.com/fixtureuser"
    assert findings[0]["status"] == "needs_validation"
    assert findings[0]["source"] == "blackbird"
    assert findings[1]["evidence"]["site"] == "reddit"


def test_blackbird_requires_username_or_email():
    with pytest.raises(ValueError, match="options.username or options.email"):
        adapter("blackbird").build({"id": "blackbird"}, "http://localhost:8765")


def test_blackbird_build_uses_the_checkout_python(monkeypatch, tmp_path):
    checkout = make_blackbird_checkout(tmp_path)
    monkeypatch.setenv("SAK_BLACKBIRD_DIR", str(checkout))
    built = adapter("blackbird").build({"id": "blackbird", "options": {"username": "fixtureuser"}}, "http://localhost:8765")
    assert built["command"][0] == str(checkout / ".venv" / "bin" / "python")
    assert str(checkout / "blackbird.py") == built["command"][1]
    assert "--username" in built["command"]
    assert "--csv" in built["command"]
    assert built["output_path"] is None


def test_blackbird_adapter_execute_parses_without_retaining_a_capture(monkeypatch, tmp_path):
    checkout = make_blackbird_checkout(tmp_path)
    monkeypatch.setenv("SAK_BLACKBIRD_DIR", str(checkout))
    run_dir = tmp_path / "unused-run"
    result = adapter("blackbird").execute(
        {"id": "blackbird", "options": {"username": "fixtureuser"}},
        "http://localhost:8765",
        run_dir=run_dir,
    )
    assert len(result["findings"]) == 1
    assert result["output_path"] is None
    assert not run_dir.exists()


def test_blackbird_does_not_claim_a_request_bound():
    assert adapter("blackbird").estimate_requests({"options": {"sites": 5}}, 60) == 0


# --------------------------------------------------------------------------- webseek


def test_webseek_dry_run_needs_no_api_key(monkeypatch, tmp_path):
    bindir = tmp_path / "bin"
    fake_binary(bindir, "npx", FAKE_NPX)
    monkeypatch.setenv("PATH", str(bindir))
    monkeypatch.delenv("WEBSEEK_API_KEY", raising=False)
    monkeypatch.delenv("WEBSEEK_PROVIDER", raising=False)

    module = adapter("webseek")
    check = module.check()
    assert check["available"] is True
    assert check["api_key_present"] is False
    assert "WEBSEEK_API_KEY" in " ".join(check["notes"])
    assert check["mcp_example"]["mcpServers"]["webseek"]["command"] == "npx"

    built = module.build({"id": "webseek", "options": {"query": "fixture query"}}, "http://localhost:8765")
    assert built["command"][0].endswith("npx")
    assert "fixture query" in built["command"]
    assert "--json" in built["command"]
    assert built["requires_scope"] is False


def test_webseek_parse_normalizes_results_and_usage():
    module = adapter("webseek")
    text = (FIXTURES / "webseek.json").read_text(encoding="utf-8")
    findings = module.parse(text)
    assert len(findings) == 2
    assert findings[0]["status"] == "needs_validation"
    assert findings[0]["source"] == "webseek"
    assert findings[0]["target"] == "https://example.test/report"
    usage = module.parse_usage(text)
    assert usage["cost_usd"] == 0.004
    assert usage["requests"] == 2


def test_webseek_adapter_execute_refuses_without_a_key(monkeypatch, tmp_path):
    bindir = tmp_path / "bin"
    fake_binary(bindir, "npx", FAKE_NPX)
    monkeypatch.setenv("PATH", str(bindir))
    monkeypatch.delenv("WEBSEEK_API_KEY", raising=False)
    result = adapter("webseek").execute(
        {"id": "webseek", "options": {"query": "fixture query"}}, "http://localhost:8765"
    )
    assert result["refused"] is True
    assert "WEBSEEK_API_KEY" in result["reason"]


def test_webseek_adapter_execute_with_a_fake_npx_parses_usage(monkeypatch, tmp_path):
    bindir = tmp_path / "bin"
    fake_binary(bindir, "npx", FAKE_NPX)
    monkeypatch.setenv("PATH", str(bindir))
    monkeypatch.setenv("WEBSEEK_API_KEY", "fixture-key-not-real")
    result = adapter("webseek").execute(
        {"id": "webseek", "options": {"query": "fixture query"}}, "http://localhost:8765"
    )
    assert len(result["findings"]) == 2
    assert result["usage"]["cost_usd"] == 0.002


# --------------------------------------------------------------------------- sanitization


def test_returned_and_durable_artifacts_are_sanitized(monkeypatch, tmp_path):
    secret = "sak-synthetic-token-9f3a"
    bindir = tmp_path / "bin"
    fake_binary(bindir, "nuclei", FAKE_NUCLEI)
    monkeypatch.setenv("PATH", str(bindir))
    monkeypatch.setenv("SAK_TEST_TOKEN", secret)
    run_dir = make_run_dir(tmp_path)
    retarget_plan(run_dir, f"http://localhost:8765/?api_key={secret}")

    report = run_module.run_step(run_dir, "nuclei", execute=True, catalog_path=CATALOG)

    assert report["ok"] is True
    rendered = json.dumps(report, default=str)
    assert secret not in rendered, "returned report leaked a synthetic credential"
    assert "***" in " ".join(report["command"])
    assert secret not in " ".join(report["command"])

    artifacts = [
        Path(report["artifacts"]["log"]),
        Path(report["artifacts"]["findings"]),
        Path(report["artifacts"]["step"]),
        run_dir / "budget.json",
    ]
    for path in artifacts:
        assert secret not in path.read_text(encoding="utf-8"), f"durable artifact leaked the secret: {path}"
    for path in run_dir.rglob("*"):
        if path.is_file() and path.name not in {"plan.json", "scope.md"}:
            assert secret not in path.read_text(encoding="utf-8", errors="replace"), path

    findings = json.loads(Path(report["artifacts"]["findings"]).read_text(encoding="utf-8"))
    assert findings[0]["status"] == "needs_validation"
    assert findings[0]["evidence"]["extracted"] == ["token=***"]
    assert "raw_output" not in json.loads(Path(report["artifacts"]["step"]).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- CLI


def test_cli_dry_run_json(monkeypatch, tmp_path, capsys):
    bindir = tmp_path / "bin"
    fake_binary(bindir, "nuclei", FAKE_NUCLEI)
    monkeypatch.setenv("PATH", str(bindir))
    run_dir = make_run_dir(tmp_path)

    code = run_module.main(
        ["--run", str(run_dir), "--step", "nuclei", "--dry-run", "--json", "--catalog", str(CATALOG)]
    )

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["dry_run"] is True
    assert payload["step"] == "nuclei"
    assert "-no-interactsh" in payload["command"]
    assert payload["scope"]["allowed"] is True
    assert payload["findings"] == []
    assert payload["destination"]["enforceable"] is True


def test_cli_execute_without_scope_exits_two(monkeypatch, tmp_path, capsys):
    bindir = tmp_path / "bin"
    fake_binary(bindir, "nuclei", FAKE_NUCLEI)
    monkeypatch.setenv("PATH", str(bindir))
    run_dir = make_run_dir(tmp_path, scope=False)

    code = run_module.main(["--run", str(run_dir), "--step", "nuclei", "--execute", "--json", "--catalog", str(CATALOG)])

    assert code == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["refused"] is True


def test_cli_unknown_step_exits_one(tmp_path, capsys):
    run_dir = make_run_dir(tmp_path)
    code = run_module.main(["--run", str(run_dir), "--step", "not-in-plan", "--dry-run", "--json", "--catalog", str(CATALOG)])
    assert code == 1
    assert "error:" in capsys.readouterr().err


def test_add_parser_follows_the_core_subcommand_convention():
    parser = argparse.ArgumentParser(prog="sak")
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_module.add_parser(subparsers)
    args = parser.parse_args(["run", "--run", "runs/x", "--step", "nuclei", "--dry-run", "--json"])
    assert args.command == "run"
    assert args.func is run_module.handle
    assert args.execute is False


def test_catalog_cards_point_at_their_adapters():
    from sak import catalog as catalog_module

    catalog = catalog_module.load_catalog(CATALOG)
    for name in ADAPTERS:
        card = catalog.find(name)
        assert card.type == "tool"
        assert card.data.get("adapter") == name
        assert card.data.get("safety", {}).get("destructive") is False
        assert card.data.get("outputs")
    assert catalog.find("nuclei").status == "verified"
    assert catalog.find("blackbird").status == "experimental"
    assert catalog.find("webseek").status == "experimental"
