from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

import pytest

from sak import findings as fm
from sak import report as rm
from sak import util

FIXTURE = Path(__file__).parent / "fixtures" / "findings-import"
NUCLEI = FIXTURE / "nuclei-candidates.json"
PLAYWRIGHT = FIXTURE / "playwright-candidates.json"
UNKNOWN = FIXTURE / "unknown-adapter-candidates.json"
EXISTING = FIXTURE / "existing-findings.json"
PATH_ESCAPE = FIXTURE / "path-escape-candidates.json"


def run_cli(argv: list[str]) -> int:
    """Exercise the findings and report parsers without the root dispatcher."""
    parser = argparse.ArgumentParser(prog="sak", add_help=False)
    subparsers = parser.add_subparsers(dest="command", required=True)
    fm.add_parser(subparsers)
    rm.add_parser(subparsers)
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except util.SakError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def import_cli(source: Path, run: Path, capsys) -> tuple[int, dict]:
    code = run_cli(["findings", "import", str(source), "--run-dir", str(run), "--json"])
    payload = json.loads(capsys.readouterr().out)
    return code, payload


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_import_candidate_list_produces_schema_valid_needs_validation_document(
    tmp_path: Path, capsys
) -> None:
    run = tmp_path / "import-test"
    code, payload = import_cli(NUCLEI, run, capsys)

    assert code == 0
    assert payload["ok"] is True
    assert payload["source"] == "nuclei-candidates.json"
    assert payload["imported"] == 2
    assert payload["skipped_duplicates"] == 0
    assert payload["total"] == 2
    assert payload["run_id"] == "import-test"

    document = load(run / "findings.json")
    assert document["run_id"] == "import-test"
    assert fm.validate_document(document, base_dir=run) == []
    assert len(document["findings"]) == 2
    assert {item["status"] for item in document["findings"]} == {"needs_validation"}
    assert {item["severity"] for item in document["findings"]} == {"high", "medium"}

    ids = {item["id"] for item in document["findings"]}
    assert "F-nuclei-fixture-sqli-localhost-8765" in ids
    supporting = [item for item in document["findings"] if item["id"].startswith("F-")]
    assert len(supporting) == 2

    for finding in document["findings"]:
        assert re.fullmatch(r"F-[A-Za-z0-9][A-Za-z0-9._-]*", finding["id"])
        assert finding["fingerprint"] == fm.fingerprint(finding)
        assert finding["open_question"]
        assert finding["next_action"]
        assert isinstance(finding["source"], dict)
        assert finding["source"]["tool"] == "nuclei"
        assert len(finding["evidence"]) == 1
        evidence = finding["evidence"][0]
        rel = Path(evidence["path"])
        assert not rel.is_absolute()
        assert rel.parts[0] == "evidence"
        stored = run / rel
        assert stored.is_file()
        assert evidence["sha256"] == fm.sha256_file(stored)
        assert evidence["kind"] == "other"
        assert evidence["producer"] == "sak findings import"
        body = load(stored)
        assert body["source"] == "nuclei-candidates.json"
        assert body["candidate"]
        assert body["imported_at"]

    assert not any(item["status"] == "confirmed" for item in document["findings"])


def test_import_document_maps_ids_severity_and_source(tmp_path: Path, capsys) -> None:
    run = tmp_path / "playwright-run"
    code, payload = import_cli(PLAYWRIGHT, run, capsys)

    assert code == 0
    assert payload["imported"] == 2
    document = load(run / "findings.json")
    findings = {item["id"]: item for item in document["findings"]}
    assert set(findings) == {"F-pw-1", "F-pw-2"}

    first = findings["F-pw-1"]
    assert first["title"] == "Stored value executes in the profile bio"
    assert first["severity"] == "high"
    assert first["asset"] == "http://127.0.0.1:8765"
    assert first["entrypoint"] == "/profile?tab=bio"
    assert first["source"] == {"tool": "playwright", "prompt": "VIBE-03"}
    assert first["status"] == "needs_validation"

    second = findings["F-pw-2"]
    assert second["severity"] == "info"
    assert second["source"] == {"tool": "playwright"}
    assert fm.validate_document(document, base_dir=run) == []


def test_import_unknown_adapter_defaults_missing_target_and_masks_secrets(
    tmp_path: Path, capsys
) -> None:
    run = tmp_path / "unknown-run"
    code, payload = import_cli(UNKNOWN, run, capsys)

    assert code == 0
    assert payload["imported"] == 2
    assert any("missing target" in warning for warning in payload["warnings"])
    assert any("severity 'unknown'" in warning for warning in payload["warnings"])

    document = load(run / "findings.json")
    findings = {item["title"]: item for item in document["findings"]}

    missing = findings["Verbose error leaks a stack trace"]
    assert missing["asset"] == fm.IMPORT_DEFAULT_ASSET
    assert missing["entrypoint"] == "/"
    assert missing["severity"] == "info"
    assert missing["principal"] == "unknown"
    assert missing["resource"] == "reported target"
    assert missing["source"] == {"tool": "mystery-adapter"}

    second = findings["Authenticated probe reached a private page"]
    assert second["severity"] == "medium"
    assert second["asset"] == "https://127.0.0.1:8765"
    assert second["entrypoint"] == "/private"

    bodies = "\n".join(
        (run / item["evidence"][0]["path"]).read_text(encoding="utf-8")
        for item in document["findings"]
    )
    assert "supersecret" not in bodies
    assert "abcdefghijklmnop" not in bodies
    assert "***" in bodies
    first_body = load(run / missing["evidence"][0]["path"])
    assert first_body["candidate"]["extra"] == {"kept": True}
    assert fm.validate_document(document, base_dir=run) == []


def test_import_appends_to_existing_findings_without_duplicating_fingerprints(
    tmp_path: Path, capsys
) -> None:
    run = tmp_path / "existing-run"
    run.mkdir()
    shutil.copyfile(EXISTING, run / "findings.json")

    code, payload = import_cli(NUCLEI, run, capsys)

    assert code == 0
    assert payload["imported"] == 1
    assert payload["skipped_duplicates"] == 1
    assert payload["total"] == 2

    document = load(run / "findings.json")
    assert fm.validate_document(document, base_dir=run) == []
    ids = {item["id"] for item in document["findings"]}
    assert "F-100" in ids
    assert "F-nuclei-fixture-sqli-localhost-8765" not in ids
    fingerprints = [fm.fingerprint(item) for item in document["findings"]]
    assert len(fingerprints) == len(set(fingerprints))
    existing = next(item for item in document["findings"] if item["id"] == "F-100")
    assert existing["status"] == "needs_validation"


def test_import_same_source_twice_is_idempotent(tmp_path: Path, capsys) -> None:
    run = tmp_path / "twice-run"
    first_code, first = import_cli(NUCLEI, run, capsys)
    second_code, second = import_cli(NUCLEI, run, capsys)

    assert first_code == 0
    assert first["imported"] == 2
    assert second_code == 0
    assert second["imported"] == 0
    assert second["skipped_duplicates"] == 2
    assert second["total"] == 2
    assert len(list((run / "evidence").glob("*-candidate.json"))) == 2
    assert fm.validate_document(load(run / "findings.json"), base_dir=run) == []


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("malformed.json", "invalid JSON"),
        ("findings-not-array.json", "'findings' must be an array"),
        ("scalar-candidates.json", "candidate 2 must be a JSON object"),
        ("top-level-scalar.json", "must contain a JSON array or object"),
        ("missing-candidates.json", "candidate source not found"),
    ],
)
def test_import_reports_malformed_input_cleanly(
    tmp_path: Path, capsys, source: str, message: str
) -> None:
    run = tmp_path / "bad-run"
    code = run_cli(
        ["findings", "import", str(FIXTURE / source), "--run-dir", str(run), "--json"]
    )
    captured = capsys.readouterr()

    assert code == 1
    assert message in captured.err
    assert captured.out == ""
    assert not (run / "findings.json").exists()
    assert not (run / "evidence").exists()


def test_import_keeps_evidence_inside_the_run_directory(tmp_path: Path, capsys) -> None:
    run = tmp_path / "safe-run"
    code, payload = import_cli(PATH_ESCAPE, run, capsys)

    assert code == 0
    assert payload["imported"] == 1
    document = load(run / "findings.json")
    finding = document["findings"][0]
    assert finding["id"] == "F-escape"
    assert re.fullmatch(r"F-[A-Za-z0-9][A-Za-z0-9._-]*", finding["id"])

    rel = Path(finding["evidence"][0]["path"])
    assert ".." not in rel.parts
    resolved = (run / rel).resolve()
    assert run.resolve() == resolved.parent or run.resolve() in resolved.parents

    outside = [
        path
        for path in tmp_path.rglob("*")
        if path.is_file() and run.resolve() not in path.resolve().parents
    ]
    assert outside == []
    assert fm.validate_document(document, base_dir=run) == []


def test_imported_findings_validate_and_render_without_confirmed_counts(
    tmp_path: Path, capsys
) -> None:
    run = tmp_path / "import-test"
    code, payload = import_cli(NUCLEI, run, capsys)
    assert code == 0
    assert payload["imported"] == 2

    code = run_cli(["findings", "validate", str(run / "findings.json"), "--json"])
    validation = json.loads(capsys.readouterr().out)
    assert code == 0
    assert validation["ok"] is True
    assert validation["findings"] == 2

    code = run_cli(["report", str(run), "--json"])
    rendered = json.loads(capsys.readouterr().out)
    assert code == 0
    assert rendered["counts"] == {
        "total": 2,
        "confirmed": 0,
        "needs_validation": 2,
        "rejected": 0,
        "excluded_confirmed": 0,
    }

    report_text = (run / "REPORT.md").read_text(encoding="utf-8")
    assert "Confirmed (verified evidence) | 0" in report_text
    assert "Findings needing validation" in report_text
    assert "Fixture SQL injection" in report_text

    detail = (run / "FINDINGS-DETAIL.md").read_text(encoding="utf-8")
    assert "F-nuclei-fixture-sqli-localhost-8765" in detail
    assert "needs_validation" in detail

    needs_validation = (run / "NEEDS-VALIDATION.md").read_text(encoding="utf-8")
    assert "Fixture SQL injection" in needs_validation
    assert "Open question" in needs_validation
