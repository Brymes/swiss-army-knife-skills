from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

import pytest

from sak import findings as fm
from sak import report as report_module
from sak import util

FIXTURE = Path(__file__).parent / "fixtures" / "findings"


def run_cli(argv: list[str]) -> int:
    """Exercise the owned report parser without the T1-owned root dispatcher."""
    parser = argparse.ArgumentParser(prog="sak", add_help=False)
    subparsers = parser.add_subparsers(dest="command", required=True)
    report_module.add_parser(subparsers)
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except util.SakError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def metadata() -> dict:
    return {
        "schema_version": "1",
        "run_id": "fixture-findings",
        "started_at": "2026-11-15T09:57:00Z",
        "ended_at": "2026-11-15T10:05:00Z",
        "target": {
            "name": "Local vulnerable fixture",
            "base_url": "http://127.0.0.1:8765",
            "scope": "localhost only",
            "authorized": True,
        },
        "suite": "web-blackbox",
        "plan": {"path": "plan.json", "run_id": "plan-1"},
        "revision": {"commit": "deadbeef", "branch": "main", "fixture_revision": "T8"},
        "operator": {"agent": "pytest", "model": "offline", "provider": "none"},
        "budget": {"seconds": 600, "requests": 100},
    }


def make_run(tmp_path: Path, *, dedupe: bool = True) -> Path:
    run = tmp_path / "report-test"
    shutil.copytree(FIXTURE, run)
    if dedupe:
        document, _ = fm.load_document(run / "findings.json")
        deduped = fm.dedupe_document(document)
        (run / "findings.json").write_text(util.dump_json(deduped), encoding="utf-8")
    (run / "run-metadata.json").write_text(json.dumps(metadata(), indent=2) + "\n", encoding="utf-8")
    return run


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_report_renders_three_artifacts_with_before_after_and_gaps(tmp_path: Path) -> None:
    run = make_run(tmp_path)
    written = report_module.write_reports(run)
    assert set(written) == {"REPORT.md", "FINDINGS-DETAIL.md", "NEEDS-VALIDATION.md"}
    assert all(path.is_file() for path in written.values())

    text = read(run / "REPORT.md")
    assert "# Assessment report — fixture-findings" in text
    assert "Local vulnerable fixture" in text
    assert "deadbeef" in text
    assert "| Candidate records | 4 | 3 |" in text
    assert "| Confirmed | 2 | 1 |" in text
    assert "| Needs validation | 1 | 1 |" in text
    assert "| Rejected | 1 | 1 |" in text
    assert "| Duplicate records removed | - | 1 |" in text
    assert "Covered 1 of 3 boundaries with verified evidence (1 excluded, 0 unverified, 1 uncovered)." in text
    assert "Authenticated browser replay was planned but not executed." in text
    assert "Admin routes are outside the authorized scope" in text
    assert "[E-sqli-request](<evidence/sqli-request.txt>)" in text


def test_valid_evidence_control_counts_confirmed_and_coverage(tmp_path: Path) -> None:
    run = make_run(tmp_path)
    report_module.write_reports(run)
    text = read(run / "REPORT.md")
    assert "| Confirmed (verified evidence) | 1 |" in text
    assert "Covered 1 of 3 boundaries with verified evidence (1 excluded, 0 unverified, 1 uncovered)." in text
    assert "Confirmed claims excluded from counts" not in text


def test_detail_and_needs_validation_carry_evidence_and_next_actions(tmp_path: Path) -> None:
    run = make_run(tmp_path)
    report_module.write_reports(run)
    document, _ = fm.load_document(run / "findings.json")
    f001 = next(item for item in document["findings"] if item["id"] == "F-001")
    detail = read(run / "FINDINGS-DETAIL.md")
    assert "### F-001 — SQL injection in the login handler" in detail
    assert f001["fingerprint"] in detail
    assert "[evidence/sqli-request.txt](<evidence/sqli-request.txt>)" in detail

    needs = read(run / "NEEDS-VALIDATION.md")
    assert "## F-002 — Reflected input on the search page" in needs
    assert "Does a browser execute the reflected value" in needs
    assert "Run the control and candidate payloads" in needs
    assert "F-001" not in needs


def test_report_masks_secrets_in_finding_text(tmp_path: Path) -> None:
    run = make_run(tmp_path)
    document, _ = fm.load_document(run / "findings.json")
    document["findings"].append(
        {
            "id": "F-009",
            "title": "Credential leak in a debug header",
            "status": "needs_validation",
            "severity": "medium",
            "asset": "http://127.0.0.1:8765",
            "entrypoint": "/debug",
            "root_cause": "header-leak",
            "principal": "anonymous",
            "resource": "debug response",
            "description": (
                "Command: curl -H 'Authorization: Bearer supersecretvalue' "
                "-H 'Cookie: session=abcdef123456' http://127.0.0.1:8765/debug"
            ),
            "open_question": "Does the production build expose the same header?",
            "next_action": "Replay with a non-admin session.",
            "created_at": "2026-11-15T10:01:00Z",
            "updated_at": "2026-11-15T10:01:00Z",
        }
    )
    (run / "findings.json").write_text(util.dump_json(document), encoding="utf-8")
    report_module.write_reports(run)
    for name in ("REPORT.md", "FINDINGS-DETAIL.md", "NEEDS-VALIDATION.md"):
        text = read(run / name)
        assert "supersecretvalue" not in text
        assert "abcdef123456" not in text
    assert "***" in read(run / "FINDINGS-DETAIL.md")


def test_empty_run_directory_renders_explicit_warnings(tmp_path: Path) -> None:
    run = tmp_path / "empty"
    run.mkdir()
    written = report_module.write_reports(run)
    text = read(written["REPORT.md"])
    assert "findings.json is missing" in text
    assert "coverage-ledger.json is missing" in text
    assert "run metadata is missing" in text
    assert "## Warnings" in text


def test_state_json_is_accepted_when_run_metadata_is_absent(tmp_path: Path) -> None:
    run = make_run(tmp_path)
    (run / "run-metadata.json").unlink()
    state = metadata()
    state["cursor"] = "opaque run-state field"
    (run / "state.json").write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    data = report_module.load_run(run)
    assert data.run_id == "fixture-findings"
    assert data.metadata["suite"] == "web-blackbox"
    assert "cursor" not in data.metadata


def test_invalid_findings_stop_the_report(tmp_path: Path) -> None:
    run = make_run(tmp_path)
    document, _ = fm.load_document(run / "findings.json")
    document["findings"][0]["evidence"] = []
    (run / "findings.json").write_text(util.dump_json(document), encoding="utf-8")
    with pytest.raises(util.SakError, match="invalid findings"):
        report_module.write_reports(run)


def test_invalid_run_metadata_stops_the_report(tmp_path: Path) -> None:
    run = make_run(tmp_path)
    broken = metadata()
    broken.pop("target")
    (run / "run-metadata.json").write_text(json.dumps(broken), encoding="utf-8")
    with pytest.raises(util.SakError, match="invalid run metadata"):
        report_module.write_reports(run)


def test_tampered_evidence_excludes_confirmed_claims_and_coverage(tmp_path: Path) -> None:
    run = make_run(tmp_path)
    before = (run / "findings.json").read_bytes()
    (run / "evidence" / "sqli-response.txt").write_text("tampered\n", encoding="utf-8")
    (run / "evidence" / "coverage-login.txt").write_text("tampered\n", encoding="utf-8")
    report_module.write_reports(run)
    assert (run / "findings.json").read_bytes() == before

    text = read(run / "REPORT.md")
    assert "| Confirmed (verified evidence) | 0 |" in text
    assert "| Confirmed claims excluded (invalid evidence) | 1 |" in text
    assert "## Confirmed claims excluded from counts" in text
    assert "F-001" in text.split("## Confirmed claims excluded from counts", 1)[1]
    assert "**hash mismatch**" in text
    assert "Covered 0 of 3 boundaries with verified evidence (1 excluded, 1 unverified, 1 uncovered)." in text
    assert "executed probe evidence is missing or failed its hash check" in text

    detail = read(run / "FINDINGS-DETAIL.md")
    assert "**Rendered as unresolved:**" in detail
    assert "**hash mismatch**" in detail
    needs = read(run / "NEEDS-VALIDATION.md")
    assert "## Confirmed claims blocked by evidence" in needs
    assert "F-001" in needs


def test_missing_evidence_excludes_confirmed_claims_and_coverage(tmp_path: Path) -> None:
    run = make_run(tmp_path)
    (run / "evidence" / "sqli-response.txt").unlink()
    (run / "evidence" / "coverage-login.txt").unlink()
    report_module.write_reports(run)

    text = read(run / "REPORT.md")
    assert "| Confirmed (verified evidence) | 0 |" in text
    assert "**missing**" in text
    assert "Covered 0 of 3 boundaries with verified evidence (1 excluded, 1 unverified, 1 uncovered)." in text
    assert "executed probe evidence is missing or failed its hash check" in text


def test_malformed_nested_findings_stop_with_a_clean_error(tmp_path: Path) -> None:
    run = make_run(tmp_path)
    document, _ = fm.load_document(run / "findings.json")
    document["findings"][0]["status_history"] = 7
    (run / "findings.json").write_text(util.dump_json(document), encoding="utf-8")
    with pytest.raises(util.SakError, match="invalid findings"):
        report_module.write_reports(run)


def test_module_cli_report_json_and_files(tmp_path: Path, capsys) -> None:
    run = make_run(tmp_path)
    code = run_cli(["report", str(run), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["ok"] is True
    assert payload["run_id"] == "fixture-findings"
    assert set(payload["written"]) == {"REPORT.md", "FINDINGS-DETAIL.md", "NEEDS-VALIDATION.md"}
    assert payload["counts"]["confirmed"] == 1
    assert payload["coverage"]["covered"] == 1
    assert (run / "REPORT.md").is_file()


def test_module_cli_report_json_reports_excluded_claims(tmp_path: Path, capsys) -> None:
    run = make_run(tmp_path)
    (run / "evidence" / "sqli-response.txt").write_text("tampered\n", encoding="utf-8")
    (run / "evidence" / "coverage-login.txt").write_text("tampered\n", encoding="utf-8")
    code = run_cli(["report", str(run), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["counts"]["confirmed"] == 0
    assert payload["counts"]["excluded_confirmed"] == 1
    assert payload["coverage"]["unverified"] == 1


def test_module_cli_report_on_empty_run_exits_zero(tmp_path: Path, capsys) -> None:
    run = tmp_path / "empty"
    run.mkdir()
    code = run_cli(["report", str(run), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["counts"]["total"] == 0
    assert payload["warnings"]


def test_missing_run_directory_is_a_clean_error(tmp_path: Path) -> None:
    with pytest.raises(util.SakError, match="does not exist"):
        report_module.write_reports(tmp_path / "absent")
