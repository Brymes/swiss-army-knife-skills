from __future__ import annotations

import argparse
import io
import json
import shutil
import sys
from pathlib import Path

import pytest

from sak import findings as fm
from sak import util

FIXTURE = Path(__file__).parent / "fixtures" / "findings"
FINDINGS = FIXTURE / "findings.json"
LEDGER = FIXTURE / "coverage-ledger.json"


def run_cli(argv: list[str]) -> int:
    """Exercise the owned findings parser without the T1-owned root dispatcher."""
    parser = argparse.ArgumentParser(prog="sak", add_help=False)
    subparsers = parser.add_subparsers(dest="command", required=True)
    fm.add_parser(subparsers)
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except util.SakError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def load(path: Path = FINDINGS) -> dict:
    document, _ = fm.load_document(path)
    return document


def copy_run(tmp_path: Path) -> Path:
    destination = tmp_path / "run"
    shutil.copytree(FIXTURE, destination)
    return destination


def test_fixture_document_and_ledger_validate() -> None:
    document = load()
    assert fm.validate_document(document, base_dir=FIXTURE) == []
    assert len(document["findings"]) == 4
    assert fm.validate_ledger(load(LEDGER), base_dir=FIXTURE, check_files=True) == []


def test_confirmed_requires_evidence_and_other_verdicts_need_their_fields() -> None:
    document = load()
    document["findings"][0]["evidence"] = []
    document["findings"][1].pop("open_question")
    document["findings"][2].pop("reason")
    issues = fm.validate_document(document, base_dir=FIXTURE, check_files=False)
    assert any("evidence" in issue["path"] and "non-empty" in issue["message"] for issue in issues)
    messages = [issue["message"] for issue in issues]
    assert any("open_question" in message for message in messages)
    assert any("reason" in message for message in messages)


def test_fingerprint_normalises_host_and_root_cause_case_only() -> None:
    first = fm.fingerprint_for("http://127.0.0.1:8765", "/login", "sql-injection", "anonymous", "users table")
    second = fm.fingerprint_for(
        "  HTTP://127.0.0.1:8765  ", "/login", "SQL-Injection", " anonymous ", " users  table "
    )
    assert first == second
    assert len(first) == 64
    assert first != fm.fingerprint_for(
        "http://127.0.0.1:8765", "/Login", "sql-injection", "anonymous", "users table"
    )
    assert first != fm.fingerprint_for(
        "http://127.0.0.1:8765", "/login", "sql-injection", "Anonymous", "users table"
    )
    assert first != fm.fingerprint_for(
        "http://127.0.0.1:8765", "/login", "sql-injection", "anonymous", "Users Table"
    )


def test_fingerprint_preserves_case_sensitive_principal_resource_and_url_path() -> None:
    account_a = fm.fingerprint_for("http://127.0.0.1:8765", "/item", "idor", "AccountA", "ItemA")
    account_lower = fm.fingerprint_for("http://127.0.0.1:8765", "/item", "idor", "accounta", "itema")
    assert account_a != account_lower
    assert account_a == fm.fingerprint_for("http://127.0.0.1:8765", "/item", "IDOR", "AccountA", "ItemA")

    path_upper = fm.fingerprint_for("http://127.0.0.1:8765/Path?Q=A", "/Item", "idor", "P", "R")
    path_lower = fm.fingerprint_for("http://127.0.0.1:8765/path?q=a", "/item", "idor", "P", "R")
    assert path_upper != path_lower


def test_fingerprint_mismatch_is_reported() -> None:
    document = load()
    document["findings"][0]["fingerprint"] = "0" * 64
    issues = fm.validate_document(document, check_files=False)
    assert any("fingerprint" in issue["message"] for issue in issues)


def test_dedupe_collapses_same_root_cause_and_is_idempotent() -> None:
    document = fm.dedupe_document(load())
    assert [item["id"] for item in document["findings"]] == ["F-001", "F-002", "F-003"]
    assert len(document["dedupe"]) == 1
    group = document["dedupe"][0]
    assert group["kept"] == "F-001"
    assert [item["id"] for item in group["removed"]] == ["F-004"]
    kept = next(item for item in document["findings"] if item["id"] == "F-001")
    assert {item["id"] for item in kept["evidence"]} == {
        "E-sqli-request",
        "E-sqli-response",
        "E-sqli-response-scanner",
    }
    again = fm.dedupe_document(document)
    assert len(again["findings"]) == 3
    assert len(again["dedupe"]) == 1


def test_dedupe_collapses_equivalent_host_and_root_cause_case() -> None:
    document = load()
    document["findings"][3]["asset"] = "HTTP://127.0.0.1:8765"
    document["findings"][3]["root_cause"] = "SQL-Injection"
    document["findings"][3]["principal"] = " anonymous "
    deduped = fm.dedupe_document(document)
    assert [item["id"] for item in deduped["findings"]] == ["F-001", "F-002", "F-003"]
    assert deduped["dedupe"][0]["kept"] == "F-001"
    again = fm.dedupe_document(deduped)
    assert len(again["findings"]) == 3
    assert len(again["dedupe"]) == 1


def test_dedupe_with_repeated_id_keeps_a_nonempty_removal_log() -> None:
    document = load()
    document["findings"].append(json.loads(json.dumps(document["findings"][0])))
    deduped = fm.dedupe_document(document)
    assert all(group["removed"] for group in deduped["dedupe"])
    assert fm.validate_document(deduped, check_files=False) == []


def test_status_transition_records_history_and_evidence(tmp_path: Path) -> None:
    run = copy_run(tmp_path)
    document = load(run / "findings.json")
    record = fm.evidence_from_file(
        "evidence/xss-note.txt",
        kind="observed",
        producer="verifier",
        base_dir=run,
    )
    updated = fm.set_status(
        document,
        "F-002",
        "confirmed",
        actor="verifier",
        evidence=[record],
        reason="Browser harness reproduced execution.",
    )
    assert updated["status"] == "confirmed"
    assert updated["status_history"][-1]["from"] == "needs_validation"
    assert updated["status_history"][-1]["to"] == "confirmed"
    assert updated["status_history"][-1]["actor"] == "verifier"
    assert updated["fingerprint"] == fm.fingerprint(updated)
    assert fm.validate_document(document, base_dir=run) == []


def test_status_gates_need_question_action_and_valid_status() -> None:
    document = load()
    with pytest.raises(util.SakError, match="open_question"):
        fm.set_status(document, "F-003", "needs_validation", actor="tester")
    with pytest.raises(util.SakError, match="next_action"):
        fm.set_status(
            document,
            "F-003",
            "needs_validation",
            actor="tester",
            open_question="Is the redirect controllable?",
        )
    reopened = fm.set_status(
        document,
        "F-003",
        "needs_validation",
        actor="tester",
        open_question="Is the redirect controllable?",
        next_action="Replay with an external host.",
    )
    assert reopened["status"] == "needs_validation"
    with pytest.raises(util.SakError, match="unknown status"):
        fm.set_status(document, "F-003", "mitigated", actor="tester")


def test_status_to_rejected_keeps_a_reason() -> None:
    document = load()
    with pytest.raises(util.SakError, match="reason"):
        fm.set_status(document, "F-002", "rejected", actor="tester")
    updated = fm.set_status(document, "F-002", "rejected", actor="tester", reason="Control did not reproduce.")
    assert updated["reason"] == "Control did not reproduce."
    assert updated["status_history"][-1]["reason"] == "Control did not reproduce."


def test_evidence_metadata_has_path_hash_timestamp_and_producer() -> None:
    record = fm.evidence_from_file(
        "evidence/sqli-request.txt",
        kind="request",
        producer="curl",
        base_dir=FIXTURE,
        timestamp="2026-11-15T10:00:00Z",
    )
    assert record["path"] == "evidence/sqli-request.txt"
    assert len(record["sha256"]) == 64
    assert record["timestamp"] == "2026-11-15T10:00:00Z"
    assert record["producer"] == "curl"
    assert record["id"].startswith("E-sqli-request-")
    with pytest.raises(util.SakError, match="evidence file not found"):
        fm.evidence_from_file("evidence/missing.txt", base_dir=FIXTURE)


def test_missing_or_tampered_evidence_file_is_reported(tmp_path: Path) -> None:
    run = copy_run(tmp_path)
    document = load(run / "findings.json")
    (run / "evidence" / "sqli-response.txt").write_text("tampered\n", encoding="utf-8")
    issues = fm.validate_document(document, base_dir=run)
    assert any("hash mismatch" in issue["message"] for issue in issues)
    (run / "evidence" / "sqli-request.txt").unlink()
    issues = fm.validate_document(document, base_dir=run)
    assert any("file not found" in issue["message"] for issue in issues)


def test_malformed_nested_shapes_return_issues_not_tracebacks(tmp_path: Path, capsys) -> None:
    document = load()
    document["findings"][0]["status_history"] = 7
    document["findings"][1]["evidence"] = {"id": "E-wrong-shape"}
    issues = fm.validate_document(document, check_files=False)
    assert issues
    assert any("status_history" in issue["path"] for issue in issues)
    assert any("evidence" in issue["path"] for issue in issues)

    ledger = load(LEDGER)
    ledger["boundaries"][0]["probes"][0]["id"] = {"bad": "id"}
    ledger["boundaries"][0]["probes"][0]["evidence"] = 7
    ledger["boundaries"][1]["probes"] = 7
    ledger_issues = fm.validate_ledger(ledger)
    assert ledger_issues
    assert any("probes" in issue["path"] for issue in ledger_issues)

    malformed = tmp_path / "malformed-findings.json"
    malformed.write_text(util.dump_json(document), encoding="utf-8")
    code = run_cli(["findings", "validate", str(malformed), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["ok"] is False
    assert payload["errors"]


def test_history_must_be_contiguous_and_end_at_status() -> None:
    document = load()
    document["findings"][0]["status_history"] = [
        {"from": "rejected", "to": "needs_validation", "at": "2026-11-15T10:00:00Z", "actor": "tester"}
    ]
    issues = fm.validate_document(document, check_files=False)
    assert any("history ends at" in issue["message"] for issue in issues)


def test_coverage_merge_executes_probes_and_keeps_exclusions() -> None:
    ledger = load(LEDGER)
    record = fm.evidence_from_file(
        "evidence/coverage-login.txt",
        kind="log",
        producer="curl",
        base_dir=FIXTURE,
    )
    incoming = {
        "schema_version": "1",
        "run_id": ledger["run_id"],
        "boundaries": [
            {
                "id": "TB-02",
                "name": "Session cookie to profile page",
                "status": "covered",
                "probes": [
                    {
                        "id": "P-02",
                        "description": "Replay the session cookie against /profile",
                        "executed": True,
                        "tool": "curl",
                        "evidence": [record],
                    },
                    {"id": "P-03", "description": "Planned header mutation", "executed": False},
                ],
            },
            {
                "id": "TB-03",
                "name": "Admin API",
                "status": "uncovered",
                "probes": [{"id": "P-04", "description": "Planned admin probe", "executed": False}],
            },
        ],
    }
    merged = fm.merge_ledger(ledger, incoming)
    summary = fm.coverage_summary(merged)
    assert summary["boundaries"] == 3
    assert summary["covered"] == 2
    assert summary["excluded"] == 1
    assert summary["uncovered"] == 0
    assert [gap["id"] for gap in fm.ledger_gaps(merged)] == ["TB-03"]
    tb02 = next(item for item in merged["boundaries"] if item["id"] == "TB-02")
    assert tb02["status"] == "covered"
    assert tb02["gap"] == "Authenticated browser replay was planned but not executed."
    planned = next(probe for probe in tb02["probes"] if probe["id"] == "P-03")
    assert planned["executed"] is False
    tb03 = next(item for item in merged["boundaries"] if item["id"] == "TB-03")
    assert tb03["status"] == "excluded"
    assert fm.validate_ledger(merged, base_dir=FIXTURE) == []


def test_coverage_status_contradiction_is_reported() -> None:
    ledger = load(LEDGER)
    ledger["boundaries"][0]["status"] = "uncovered"
    issues = fm.validate_ledger(ledger)
    assert any("contradicts probes" in issue["message"] for issue in issues)


def test_mask_text_hides_headers_cookies_keys_and_tokens() -> None:
    aws_key = "AKIA" + "ABCDEFGHIJKLMNOP"
    github_token = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
    text = (
        "Authorization: Bearer supersecretvalue\n"
        "Cookie: session=abcdef123456\n"
        '{"password": "hunter2", "api_key": "keyvalue"}\n'
        f"{aws_key}\n"
        f"{github_token}\n"
    )
    masked = fm.mask_text(text)
    for raw in ("supersecretvalue", "abcdef123456", "hunter2", "keyvalue", aws_key, github_token):
        assert raw not in masked
    assert "***" in masked


def test_module_cli_validate_json(capsys) -> None:
    code = run_cli(["findings", "validate", str(FINDINGS), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["ok"] is True
    assert payload["findings"] == 4


def test_module_cli_dedupe_json(capsys) -> None:
    code = run_cli(["findings", "dedupe", str(FINDINGS), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert len(payload["findings"]) == 3
    assert payload["dedupe"][0]["removed"][0]["id"] == "F-004"


def test_module_cli_add_from_stdin_merges_and_writes(tmp_path: Path, monkeypatch, capsys) -> None:
    run = copy_run(tmp_path)
    destination = run / "findings.json"
    incoming = {
        "id": "F-005",
        "title": "Directory listing on the static mount",
        "status": "needs_validation",
        "severity": "low",
        "asset": "http://127.0.0.1:8765",
        "entrypoint": "/static/",
        "root_cause": "directory-listing",
        "principal": "anonymous",
        "resource": "static files",
        "open_question": "Does the listing include a file that should be private?",
        "next_action": "Fetch the listing and compare it with the shipped asset list.",
    }
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(incoming)))
    code = run_cli(["findings", "add", "-", "--file", str(destination), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["added"] == 1
    assert payload["duplicates_removed"] == 1
    assert payload["total"] == 4
    written = json.loads(destination.read_text(encoding="utf-8"))
    ids = {item["id"] for item in written["findings"]}
    assert "F-005" in ids
    assert "F-004" not in ids


def test_module_cli_status_errors_then_succeeds(tmp_path: Path, capsys) -> None:
    run = copy_run(tmp_path)
    destination = run / "findings.json"
    code = run_cli(["findings", "status", "F-003", "needs_validation", "--file", str(destination)])
    assert code == 1
    assert "open_question" in capsys.readouterr().err
    code = run_cli(
        [
            "findings",
            "status",
            "F-003",
            "needs_validation",
            "--file",
            str(destination),
            "--open-question",
            "Is the target controllable?",
            "--next-action",
            "Replay with an external host.",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["finding"]["status"] == "needs_validation"
    written = json.loads(destination.read_text(encoding="utf-8"))
    reopened = next(item for item in written["findings"] if item["id"] == "F-003")
    assert reopened["open_question"] == "Is the target controllable?"


def test_module_cli_status_rejects_wrong_type_history_without_writing(tmp_path: Path, capsys) -> None:
    run = copy_run(tmp_path)
    destination = run / "findings.json"
    document = load(destination)
    document["findings"][1]["status_history"] = 7
    destination.write_text(util.dump_json(document), encoding="utf-8")
    before = destination.read_bytes()
    code = run_cli(
        [
            "findings",
            "status",
            "F-002",
            "rejected",
            "--file",
            str(destination),
            "--reason",
            "Control did not reproduce.",
        ]
    )
    assert code == 1
    assert "invalid findings" in capsys.readouterr().err
    assert destination.read_bytes() == before


def test_module_cli_list_filters_and_json(capsys) -> None:
    code = run_cli(["findings", "list", str(FINDINGS), "--status", "confirmed", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert {item["id"] for item in payload} == {"F-001", "F-004"}
