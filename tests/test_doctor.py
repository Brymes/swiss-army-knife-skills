from __future__ import annotations

import json

from sak import doctor
from sak.__main__ import main


def test_collect_includes_pinned_toolchain() -> None:
    report = doctor.collect()
    tools = {tool["name"]: tool for tool in report["tools"]}
    assert {"python3.12", "uv", "git", "node", "npm", "nuclei", "docker"} <= set(tools)
    assert tools["python3.12"]["installed"] is True
    assert report["python"]["meets_requirement"] is True


def test_missing_tool_has_install_hint() -> None:
    status = doctor.detect_tool("sak-tool-that-does-not-exist")
    assert status.installed is False
    assert status.install_hint
    assert status.required is False


def test_availability_helpers() -> None:
    assert doctor.is_available("python3") is True
    assert doctor.is_available("sak-tool-that-does-not-exist") is False
    assert doctor.is_available("SAK_FIXTURE_ENV_VAR_THAT_IS_UNSET") is False


def test_cli_doctor_json(capsys) -> None:
    code = main(["doctor", "--json"])
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True
    assert "tools" in report
    assert isinstance(report["missing"], list)
