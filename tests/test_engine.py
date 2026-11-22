from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from sak import engine, util
from sak.__main__ import main


def write_engine(
    root: Path,
    engine_id: str = "fixture-engine",
    requirements: list[str] | None = None,
    include_commands: bool = True,
    env: dict[str, str] | None = None,
    commands: dict[str, str] | None = None,
) -> Path:
    engines = root / "engines"
    engines.mkdir(parents=True)
    data = {
        "id": engine_id,
        "name": "Fixture Engine",
        "description": "Offline engine used by tests.",
        "license": "MIT",
        "requirements": requirements or ["python3"],
    }
    if commands is not None:
        data["commands"] = commands
    elif include_commands:
        data["commands"] = {
            "install": "echo install",
            "up": "echo up",
            "down": "echo down",
            "status": "echo status",
        }
    if env is not None:
        data["env"] = env
    path = engines / f"{engine_id}.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def test_load_and_list_engines(tmp_path: Path, capsys) -> None:
    write_engine(tmp_path)
    loaded = engine.load_engines(tmp_path)
    assert [card.id for card in loaded] == ["fixture-engine"]

    code = main(["engine", "list", "--root", str(tmp_path), "--json"])
    assert code == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed[0]["id"] == "fixture-engine"
    assert listed[0]["ready"] is True


def test_missing_directory_is_empty(tmp_path: Path, capsys) -> None:
    assert engine.load_engines(tmp_path) == []
    code = main(["engine", "list", "--root", str(tmp_path), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out) == []


def test_doctor_reports_missing_runtime(tmp_path: Path, capsys) -> None:
    write_engine(tmp_path, requirements=["sak-missing-runtime"])
    report = engine._engine_report(engine.load_engines(tmp_path)[0])
    assert report["ready"] is False
    assert report["missing"] == ["sak-missing-runtime"]

    code = main(["engine", "doctor", "fixture-engine", "--root", str(tmp_path), "--json"])
    assert code == 0
    doctor_report = json.loads(capsys.readouterr().out)
    assert doctor_report[0]["ready"] is False


def test_dry_run_never_executes(tmp_path: Path, monkeypatch) -> None:
    write_engine(tmp_path)

    def fail(*args, **kwargs):
        raise AssertionError("subprocess must not run in dry-run mode")

    monkeypatch.setattr(engine.subprocess, "run", fail)
    report = engine.run_action(tmp_path, "fixture-engine", "install")
    assert report["dry_run"] is True
    assert report["ok"] is True
    assert report["commands"] == ["echo install"]


def test_execute_refuses_missing_runtime(tmp_path: Path, monkeypatch) -> None:
    write_engine(tmp_path, requirements=["sak-missing-runtime"])

    def fail(*args, **kwargs):
        raise AssertionError("subprocess must not run when requirements are missing")

    monkeypatch.setattr(engine.subprocess, "run", fail)
    report = engine.run_action(tmp_path, "fixture-engine", "up", execute=True)
    assert report["ok"] is False
    assert report["refused"] is True
    assert "sak-missing-runtime" in report["reason"]
    assert report["hints"]


def test_execute_runs_when_ready(tmp_path: Path, monkeypatch) -> None:
    write_engine(tmp_path, requirements=["python3"])
    calls: list[str] = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(engine.subprocess, "run", fake_run)
    report = engine.run_action(tmp_path, "fixture-engine", "status", execute=True)
    assert report["ok"] is True
    assert calls == ["echo status"]


def test_invalid_engine_card_is_rejected(tmp_path: Path) -> None:
    write_engine(tmp_path, include_commands=False)
    with pytest.raises(util.EngineError):
        engine.load_engines(tmp_path)


def test_secret_values_are_masked_in_dry_runs_and_results(tmp_path: Path, monkeypatch) -> None:
    secret = "fake-secret-value-123"
    command = f"curl -H 'Authorization: Bearer {secret}' http://127.0.0.1/"
    write_engine(
        tmp_path,
        env={"FAKE_API_KEY": secret},
        commands={
            "install": "echo install",
            "up": "echo up",
            "down": "echo down",
            "status": command,
        },
    )

    dry_run = engine.run_action(tmp_path, "fixture-engine", "status")
    assert secret not in json.dumps(dry_run)
    assert "***" in dry_run["commands"][0]

    calls: list[str] = []

    def fake_run(raw_command, **kwargs):
        calls.append(raw_command)
        return SimpleNamespace(
            returncode=0,
            stdout=f"Authorization: Bearer {secret}\n",
            stderr=f"api_key={secret}\n",
        )

    monkeypatch.setattr(engine.subprocess, "run", fake_run)
    report = engine.run_action(tmp_path, "fixture-engine", "status", execute=True)
    assert calls == [command]
    assert secret not in json.dumps(report)
    assert "***" in report["results"][0]["stdout"]
    assert "***" in report["results"][0]["stderr"]


def test_mask_secrets_patterns() -> None:
    text = (
        "Authorization: Bearer abcdef123456\n"
        "Cookie: session=abcdef\n"
        "api_key=supersecret\n"
        "password: hunter2\n"
    )
    masked = util.mask_secrets(text)
    for value in ("abcdef123456", "session=abcdef", "supersecret", "hunter2"):
        assert value not in masked
    assert "***" in masked
    assert util.secret_env_values({"FAKE_API_KEY": "x", "PLAIN_VALUE": "y"}) == ["x"]


def test_mask_secrets_quoted_json_and_short_values() -> None:
    text = json.dumps({"api_key": "value with spaces", "note": "keep me"})
    masked = util.mask_secrets(text)
    assert "value with spaces" not in masked
    assert "keep me" in masked
    assert '"api_key": "***"' in masked
    assert util.mask_secrets("ab", ["ab"]) == "***"


def test_inherited_environment_secrets_are_masked(tmp_path: Path, monkeypatch) -> None:
    secret = "inherited-fake-secret-456"
    monkeypatch.setenv("FAKE_API_KEY", secret)
    write_engine(tmp_path)

    def fake_run(raw_command, **kwargs):
        assert kwargs["env"]["FAKE_API_KEY"] == secret
        return SimpleNamespace(
            returncode=0,
            stdout=f"Authorization: Bearer {secret}\n",
            stderr=secret + "\n",
        )

    monkeypatch.setattr(engine.subprocess, "run", fake_run)
    report = engine.run_action(tmp_path, "fixture-engine", "status", execute=True)
    assert secret not in json.dumps(report)
    assert "***" in report["results"][0]["stdout"]


def test_card_env_precedence_and_both_secret_values_are_masked(tmp_path: Path, monkeypatch) -> None:
    inherited = "inherited-fake-secret-789"
    card_value = "card-fake-secret-012"
    monkeypatch.setenv("FAKE_API_KEY", inherited)
    write_engine(tmp_path, env={"FAKE_API_KEY": card_value})
    seen_env: dict[str, str] = {}

    def fake_run(raw_command, **kwargs):
        seen_env.update(kwargs["env"])
        return SimpleNamespace(
            returncode=0,
            stdout=f"{inherited} {card_value}\n",
            stderr="",
        )

    monkeypatch.setattr(engine.subprocess, "run", fake_run)
    report = engine.run_action(tmp_path, "fixture-engine", "status", execute=True)
    assert seen_env["FAKE_API_KEY"] == card_value
    dumped = json.dumps(report)
    assert inherited not in dumped
    assert card_value not in dumped
