"""Offline tests for the bounded ``sak hunt`` runner."""

from __future__ import annotations

import json
import time
from pathlib import Path

from sak import hunt

FIXTURE = Path(__file__).parent / "fixtures" / "hunt" / "fake-runner"
TARGET = "http://127.0.0.1:8080"


def runner(mode: str = "") -> str:
    suffix = f" {mode}" if mode else ""
    return f"{FIXTURE}{suffix}"


def read_record(run_dir: Path, prompt_id: str = "INV-01") -> dict:
    return json.loads((run_dir / "hunt" / f"{prompt_id}.json").read_text(encoding="utf-8"))


def test_success_writes_sanitized_record(tmp_path, capsys):
    run_dir = tmp_path / "run-success"
    code = hunt.main(
        [
            "--run",
            str(run_dir),
            "--target",
            TARGET,
            "--prompts",
            "INV-01",
            "--runner",
            runner(),
            "--json",
        ]
    )
    output = capsys.readouterr()
    assert code == 0, output.err
    summary = json.loads(output.out)
    assert summary["ok"] is True
    assert summary["counts"] == {"prompts": 1, "success": 1, "errors": 0, "candidates": 1}

    record = read_record(run_dir)
    assert record["prompt"] == "INV-01"
    assert record["target"] == TARGET
    assert record["status"] == "success"
    assert record["exit"] == 0
    assert record["duration_seconds"] >= 0
    assert record["error"] is None
    assert len(record["candidates"]) == 1
    candidate = record["candidates"][0]
    assert candidate["status"] == "needs_validation"
    assert candidate["source"]["prompt"] == "INV-01"

    serialized = json.dumps(record)
    for secret in (
        "fake-bearer-token-abc123",
        "deadbeefcafebabe",
        "secretpass",
        "hunter2",
        "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake1234",
    ):
        assert secret not in serialized, secret
    assert "***" in serialized


def test_candidate_parsing_and_normalization(tmp_path, capsys):
    run_dir = tmp_path / "run-candidates"
    code = hunt.main(
        [
            "--run",
            str(run_dir),
            "--target",
            TARGET,
            "--prompts",
            "INV-01",
            "--runner",
            runner("candidate"),
            "--json",
        ]
    )
    assert code == 0, capsys.readouterr().err
    candidates = read_record(run_dir)["candidates"]
    assert [candidate["id"] for candidate in candidates] == ["C-1", "C-2", "INV-01-C04"]
    first, second, generated = candidates
    assert first["severity"] == "medium"
    assert first["root_cause"] == "moderate-path-traversal"
    assert first["principal"] == "lowpriv"
    assert first["entrypoint"] == "/download?file=../app.py"
    assert "***" in first["target"]
    assert second["severity"] == "info"
    assert second["entrypoint"] == "/profile?id=2"
    assert generated["id"].startswith("INV-01-C")
    assert all(candidate["status"] == "needs_validation" for candidate in candidates)


def test_failed_hunter_is_an_error_not_a_finding(tmp_path, capsys):
    run_dir = tmp_path / "run-fail"
    code = hunt.main(
        [
            "--run",
            str(run_dir),
            "--target",
            TARGET,
            "--prompts",
            "INV-01",
            "--runner",
            runner("fail"),
            "--json",
        ]
    )
    output = capsys.readouterr()
    assert code == 1
    assert json.loads(output.out)["ok"] is False
    record = read_record(run_dir)
    assert record["status"] == "error"
    assert record["exit"] == 2
    assert record["candidates"] == []
    assert "exited with code 2" in record["error"]
    assert "hunter2" not in json.dumps(record)


def test_timeout_is_recorded_as_an_error(tmp_path, capsys):
    run_dir = tmp_path / "run-timeout"
    started = time.monotonic()
    code = hunt.main(
        [
            "--run",
            str(run_dir),
            "--target",
            TARGET,
            "--prompts",
            "INV-01",
            "--runner",
            runner("timeout"),
            "--timeout",
            "0.25",
            "--json",
        ]
    )
    elapsed = time.monotonic() - started
    assert code == 1
    assert elapsed < 5
    record = read_record(run_dir)
    assert record["status"] == "error"
    assert record["timed_out"] is True
    assert "timeout" in record["error"]
    assert record["candidates"] == []


def test_concurrency_cap_is_enforced(tmp_path, capsys, monkeypatch):
    log_path = tmp_path / "hunt.log"
    monkeypatch.setenv("FAKE_HUNT_LOG", str(log_path))
    run_dir = tmp_path / "run-concurrency"
    code = hunt.main(
        [
            "--run",
            str(run_dir),
            "--target",
            TARGET,
            "--prompts",
            "INV-01,INV-02,INV-03",
            "--runner",
            runner("concurrency"),
            "--max-agents",
            "2",
            "--timeout",
            "5",
            "--json",
        ]
    )
    assert code == 0, capsys.readouterr().err

    starts: dict[str, float] = {}
    ends: dict[str, float] = {}
    for line in log_path.read_text(encoding="utf-8").splitlines():
        kind, pid, stamp = line.split()
        (starts if kind == "start" else ends)[pid] = float(stamp)
    assert len(starts) == 3
    events = sorted(
        [(stamp, 1) for stamp in starts.values()] + [(stamp, -1) for stamp in ends.values()]
    )
    overlap = peak = 0
    for _, delta in events:
        overlap += delta
        peak = max(peak, overlap)
    assert peak == 2
    for prompt_id in ("INV-01", "INV-02", "INV-03"):
        assert read_record(run_dir, prompt_id)["status"] == "success"


def test_jsonl_events_extract_final_agent_candidate(tmp_path, capsys):
    run_dir = tmp_path / "run-jsonl"
    code = hunt.main(
        [
            "--run",
            str(run_dir),
            "--target",
            TARGET,
            "--prompts",
            "INV-01",
            "--runner",
            runner("jsonl"),
            "--json",
        ]
    )
    assert code == 0, capsys.readouterr().err
    record = read_record(run_dir)
    assert record["status"] == "success"
    assert "step_start" in record["stdout"]
    assert [candidate["id"] for candidate in record["candidates"]] == ["J-1"]
    candidate = record["candidates"][0]
    assert candidate["status"] == "needs_validation"
    assert candidate["entrypoint"] == "/profile?id=2"
    assert candidate["root_cause"] == "missing-object-owner-check"


def test_jsonl_events_without_candidate_json_are_an_error(tmp_path, capsys):
    run_dir = tmp_path / "run-jsonl-empty"
    code = hunt.main(
        [
            "--run",
            str(run_dir),
            "--target",
            TARGET,
            "--prompts",
            "INV-01",
            "--runner",
            runner("jsonl-no-candidate"),
            "--json",
        ]
    )
    assert code == 1
    record = read_record(run_dir)
    assert record["status"] == "error"
    assert "no candidate JSON" in record["error"]
    assert record["candidates"] == []


def test_live_style_event_fixture_is_parsed():
    stream = (Path(__file__).parent / "fixtures" / "hunt" / "opencode-events.jsonl").read_text(
        encoding="utf-8"
    )
    data = hunt.parse_runner_output(stream)
    assert data["candidates"][0]["id"] == "E-1"
    assert data["candidates"][0]["target"] == f"{TARGET}/profile?id=2"


def test_default_runner_uses_json_event_mode(monkeypatch):
    monkeypatch.setattr(hunt, "_opencode_executable", lambda: "opencode")
    monkeypatch.setattr(hunt, "_supports_standalone", lambda executable: True)
    assert hunt.runner_command(None, "nearai/example") == [
        "opencode",
        "run",
        "--standalone",
        "--format",
        "json",
        "--model",
        "nearai/example",
    ]


def test_default_runner_omits_standalone_on_older_opencode(monkeypatch):
    monkeypatch.setattr(hunt, "_opencode_executable", lambda: "opencode")
    monkeypatch.setattr(hunt, "_supports_standalone", lambda executable: False)
    assert hunt.runner_command(None, "nearai/example") == [
        "opencode",
        "run",
        "--format",
        "json",
        "--model",
        "nearai/example",
    ]


def test_runner_override_stays_compatible():
    assert hunt.runner_command("fake --flag", "ignored") == ["fake", "--flag"]


def test_broken_json_is_an_error(tmp_path, capsys):
    run_dir = tmp_path / "run-broken"
    code = hunt.main(
        [
            "--run",
            str(run_dir),
            "--target",
            TARGET,
            "--prompts",
            "INV-01",
            "--runner",
            runner("broken"),
            "--json",
        ]
    )
    assert code == 1
    record = read_record(run_dir)
    assert record["status"] == "error"
    assert "invalid JSON" in record["error"]
    assert record["candidates"] == []


def test_no_prompt_cards_in_catalog(tmp_path, capsys):
    empty = tmp_path / "empty-catalog"
    empty.mkdir()
    code = hunt.main(
        [
            "--run",
            str(tmp_path / "run-empty"),
            "--target",
            TARGET,
            "--prompts",
            "INV-01",
            "--catalog",
            str(empty),
            "--runner",
            runner(),
        ]
    )
    output = capsys.readouterr()
    assert code == 1
    assert "no prompt cards" in output.err


def test_scope_mismatch_refuses_to_launch_a_hunter(tmp_path, capsys):
    run_dir = tmp_path / "run-scope"
    run_dir.mkdir()
    (run_dir / "scope.md").write_text(
        "# Scope\n\n## Allowed hosts\n- example.internal:443\n",
        encoding="utf-8",
    )
    code = hunt.main(
        [
            "--run",
            str(run_dir),
            "--target",
            TARGET,
            "--prompts",
            "INV-01",
            "--runner",
            runner(),
            "--json",
        ]
    )
    assert code == 1
    record = read_record(run_dir)
    assert record["status"] == "error"
    assert "not authorized" in record["error"]
    assert record["candidates"] == []
    assert record["scope"]["allowed"] is False


def test_empty_prompt_list_is_rejected(tmp_path, capsys):
    code = hunt.main(
        [
            "--run",
            str(tmp_path / "run-empty-prompts"),
            "--target",
            TARGET,
            "--prompts",
            " , ",
            "--runner",
            runner(),
        ]
    )
    assert code == 1
    assert "no prompt ids" in capsys.readouterr().err


def test_prompt_budget_is_enforced(tmp_path, capsys):
    ids = ",".join(f"INV-{index:02d}" for index in range(1, hunt.MAX_PROMPTS + 2))
    code = hunt.main(
        [
            "--run",
            str(tmp_path / "run-budget"),
            "--target",
            TARGET,
            "--prompts",
            ids,
            "--runner",
            runner(),
        ]
    )
    assert code == 1
    assert "prompt budget exceeded" in capsys.readouterr().err


def test_rendered_prompt_carries_target_scope_and_black_box_rule(tmp_path, capsys, monkeypatch):
    prompts_dir = tmp_path / "prompts"
    monkeypatch.setenv("FAKE_HUNT_PROMPT_DIR", str(prompts_dir))
    monkeypatch.setenv("SAK_HUNT_ACCOUNT", "lowpriv-fixture")
    run_dir = tmp_path / "run-context"
    code = hunt.main(
        [
            "--run",
            str(run_dir),
            "--target",
            TARGET,
            "--prompts",
            "INV-01",
            "--runner",
            runner(),
        ]
    )
    assert code == 0, capsys.readouterr().err
    prompt = next(prompts_dir.glob("prompt-*.txt")).read_text(encoding="utf-8")
    assert TARGET in prompt
    assert "lowpriv-fixture" in prompt
    assert "Never read target source code" in prompt
    assert "INV-01" in prompt
    assert '"candidates"' in prompt


def test_bare_run_name_lives_under_runs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert hunt.resolve_run_dir("hunt-test") == Path("runs/hunt-test")
    assert hunt.resolve_run_dir("runs/hunt-test") == Path("runs/hunt-test")



