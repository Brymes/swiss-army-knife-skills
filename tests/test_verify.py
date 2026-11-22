"""Offline tests for expected-issue verification and scoring.

The verification fixtures are built here rather than committed under
``tests/fixtures/verify`` because the task's Owns list does not include that
directory.  :func:`ensure_fixture` writes the deterministic fixture tree the
brief names (``tests/fixtures/verify/profile.yaml`` and ``runs/verify-test``) so
the offline CLI command can run after collection.  Every test also works from a
``tmp_path`` copy; no live target or network is used.
"""

from __future__ import annotations

import json
import shutil
from hashlib import sha256
from pathlib import Path

import pytest

from sak import findings as findings_module
from sak import util
from sak import verify as verify_module

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "verify"
CLI_RUN_DIR = REPO_ROOT / "runs" / "verify-test"
PROFILE = FIXTURE_DIR / "profile.yaml"
RUN_FIXTURE = FIXTURE_DIR / "run"

PROFILE_YAML = """\
# Offline verification fixture — synthetic target, no live host.
schema: sak.blackbox.profile.v1
target:
  id: verify-fixture
  name: Offline verification fixture
  base_url: http://127.0.0.1:8766
  authorized: true
accounts:
  - id: fixture-user
    role: tester
    username: fixture
    lab_default: fixture-password
auth:
  login:
    method: POST
    path: /login
  csrf:
    required: false
scope:
  allowed_hosts:
    - 127.0.0.1:8766
  requires_scope_file: false
budget:
  max_requests: 20
  max_seconds: 30
expected:
  - id: VRF-SQLI-01
    title: SQL injection returns fixture rows
    class: sql-injection
    cwe: CWE-89
    method: GET
    endpoint: /item?id=1
    proof: A UNION payload returns the fixture marker row.
    severity: high
    default: true
  - id: VRF-XSS-01
    title: Reflected XSS in the echo parameter
    class: xss-reflected
    cwe: CWE-79
    method: GET
    endpoint: /echo?name=test
    proof: The payload is reflected unencoded.
    severity: medium
    default: true
  - id: VRF-CMDI-01
    title: Command injection on the ping page
    class: command-injection
    cwe: CWE-78
    method: POST
    endpoint: /ping
    proof: The id command returns uid and gid.
    severity: high
    default: true
  - id: VRF-IDOR-01
    title: Second principal reads another account
    class: idor
    cwe: CWE-639
    method: GET
    endpoint: /account/1
    proof: A second principal reads the owner's record.
    severity: high
    default: true
  - id: VRF-UPLOAD-01
    title: Unrestricted upload executes a marker
    class: unrestricted-upload
    cwe: CWE-434
    method: POST
    endpoint: /upload
    proof: The uploaded marker is served and executed.
    severity: critical
    default: false
safety:
  intrusive_requires_approval: true
  accounts_are_lab_only: true
"""

DUPLICATE_PROFILE_YAML = """\
schema: sak.blackbox.profile.v1
target:
  id: duplicate-fixture
  base_url: http://127.0.0.1:8766
accounts:
  - id: fixture-user
    username: fixture
    lab_default: fixture-password
expected:
  - id: VRF-DUP-01
    title: First duplicate
    class: sql-injection
    endpoint: /item?id=1
  - id: VRF-DUP-01
    title: Second duplicate
    class: xss-reflected
    endpoint: /echo?name=test
"""

FIXED_TIME = "2026-11-20T10:00:00Z"
SQLI_RESPONSE = (
    "id=1' UNION SELECT user, password FROM users-- -\n"
    "admin|5f4dcc3b5aa765d61d8327deb882cf99\n"
)


def _finding(
    *,
    identifier: str,
    status: str,
    title: str,
    entrypoint: str,
    root_cause: str,
    tags: list[str] | None = None,
    evidence: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    finding: dict[str, object] = {
        "id": identifier,
        "title": title,
        "status": status,
        "severity": "high",
        "asset": "http://127.0.0.1:8766",
        "entrypoint": entrypoint,
        "root_cause": root_cause,
        "principal": "fixture-user",
        "resource": entrypoint,
        "source": {"tool": "verify-fixture"},
        "created_at": FIXED_TIME,
        "updated_at": FIXED_TIME,
    }
    if tags:
        finding["tags"] = tags
    if evidence:
        finding["evidence"] = evidence
    if status == "needs_validation":
        finding["open_question"] = "Does the fixture proof reproduce?"
        finding["next_action"] = "Replay the fixture check."
    if status == "rejected":
        finding["reason"] = "the fixture check observed a failure"
    finding["fingerprint"] = findings_module.fingerprint(finding)
    return finding


def _evidence(path: str, digest: str, identifier: str = "E-fixture-proof") -> dict[str, object]:
    return {
        "id": identifier,
        "kind": "observed",
        "path": path,
        "sha256": digest,
        "timestamp": FIXED_TIME,
        "producer": "verify-fixture",
    }


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(util.dump_json(data), encoding="utf-8")


def build_run_tree(root: Path) -> None:
    """Write the deterministic synthetic run tree under ``root``."""
    evidence_dir = root / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "sqli-response.txt").write_text(SQLI_RESPONSE, encoding="utf-8")
    digest = sha256((evidence_dir / "sqli-response.txt").read_bytes()).hexdigest()
    missing_digest = "0" * 64

    document = {
        "schema_version": "1",
        "run_id": root.name,
        "generated_at": FIXED_TIME,
        "findings": [
            _finding(
                identifier="F-sqli-confirmed",
                status="confirmed",
                title="SQL injection returns the fixture users row",
                entrypoint="/item?id=1",
                root_cause="sql-injection",
                tags=["VRF-SQLI-01"],
                evidence=[_evidence("evidence/sqli-response.txt", digest)],
            ),
            _finding(
                identifier="F-cmdi-missing-evidence",
                status="confirmed",
                title="Command injection record with a missing evidence file",
                entrypoint="/ping",
                root_cause="command-injection",
                tags=["VRF-CMDI-01"],
                evidence=[_evidence("evidence/missing-ping.txt", missing_digest, "E-cmdi-missing")],
            ),
            _finding(
                identifier="F-extra-info",
                status="needs_validation",
                title="Unmapped information disclosure candidate",
                entrypoint="/misc",
                root_cause="info-disclosure",
            ),
            _finding(
                identifier="F-unknown-tag",
                status="needs_validation",
                title="Record that names an unknown rubric id",
                entrypoint="/other",
                root_cause="info-disclosure",
                tags=["rubric:VRF-DOES-NOT-EXIST"],
            ),
        ],
        "dedupe": [],
    }
    _write_json(root / "findings.json", document)

    _write_json(
        root / "exploit" / "VRF-SQLI-01.json",
        {
            "schema": "sak.blackbox.exploit.v1",
            "run": root.name,
            "check": "VRF-SQLI-01",
            "action": "sql_injection",
            "status": "confirmed",
            "proof": True,
            "proof_condition": "the UNION payload returns the fixture marker row",
            "reason": "marker returned by the payload",
            "evidence": [{"label": "sql payload", "response": {"status": 200}}],
            "requests": 2,
        },
    )
    _write_json(
        root / "exploit" / "VRF-IDOR-01.json",
        {
            "schema": "sak.blackbox.exploit.v1",
            "run": root.name,
            "check": "VRF-IDOR-01",
            "action": "idor",
            "status": "rejected",
            "proof": False,
            "proof_condition": "a second principal reads the owner's record",
            "reason": "second principal received 403",
            "evidence": [{"label": "foreign read", "response": {"status": 403}}],
            "requests": 2,
        },
    )
    _write_json(
        root / "hunt" / "inv-xss.json",
        {
            "schema_version": "1",
            "prompt": "inv-xss",
            "status": "success",
            "exit": 0,
            "candidates": [
                {
                    "id": "C-1",
                    "prompt": "inv-xss",
                    "title": "Reflected echo candidate",
                    "status": "needs_validation",
                    "severity": "medium",
                    "target": "http://127.0.0.1:8766",
                    "entrypoint": "/echo?name=test",
                    "root_cause": "xss-reflected",
                    "principal": "fixture-user",
                    "resource": "/echo",
                }
            ],
        },
    )


def ensure_fixture() -> None:
    """Materialize the named fixture paths if they are missing or stale."""
    if not PROFILE.is_file() or PROFILE.read_text(encoding="utf-8") != PROFILE_YAML:
        PROFILE.parent.mkdir(parents=True, exist_ok=True)
        PROFILE.write_text(PROFILE_YAML, encoding="utf-8")
    duplicate = FIXTURE_DIR / "duplicate-profile.yaml"
    if not duplicate.is_file() or duplicate.read_text(encoding="utf-8") != DUPLICATE_PROFILE_YAML:
        duplicate.write_text(DUPLICATE_PROFILE_YAML, encoding="utf-8")
    build_run_tree(RUN_FIXTURE)
    if CLI_RUN_DIR.exists():
        shutil.rmtree(CLI_RUN_DIR)
    shutil.copytree(RUN_FIXTURE, CLI_RUN_DIR)
    # The run id must match the copied directory name for readable output.
    document = json.loads((CLI_RUN_DIR / "findings.json").read_text(encoding="utf-8"))
    document["run_id"] = CLI_RUN_DIR.name
    (CLI_RUN_DIR / "findings.json").write_text(util.dump_json(document), encoding="utf-8")


ensure_fixture()


@pytest.fixture()
def scored() -> dict:
    result = verify_module.score_run(RUN_FIXTURE, PROFILE)
    return result


def _by_id(result: dict, issue_id: str) -> dict:
    return next(issue for issue in result["issues"] if issue["id"] == issue_id)


def test_verdicts_and_coverage_classes(scored: dict) -> None:
    assert _by_id(scored, "VRF-SQLI-01")["verdict"] == "confirmed"
    assert _by_id(scored, "VRF-SQLI-01")["coverage"] == "covered"
    assert _by_id(scored, "VRF-XSS-01")["verdict"] == "needs_validation"
    assert _by_id(scored, "VRF-XSS-01")["coverage"] == "partial"
    assert _by_id(scored, "VRF-IDOR-01")["verdict"] == "rejected"
    assert _by_id(scored, "VRF-IDOR-01")["coverage"] == "missed"
    assert _by_id(scored, "VRF-UPLOAD-01")["verdict"] == "none"
    assert _by_id(scored, "VRF-UPLOAD-01")["coverage"] == "deferred"
    assert scored["rubric"] == {
        "expected": 5,
        "confirmed": 1,
        "needs_validation": 2,
        "rejected": 1,
        "unattempted": 1,
        "coverage": {"covered": 1, "partial": 2, "missed": 1, "deferred": 1, "ratio": 0.2},
    }


def test_missing_evidence_never_confirms(scored: dict) -> None:
    issue = _by_id(scored, "VRF-CMDI-01")
    assert issue["verdict"] == "needs_validation"
    assert issue["coverage"] == "partial"
    assert any("missing" in note for note in issue["notes"])
    assert issue["evidence"] == []


def test_hunter_candidate_is_partial_and_never_promoted(scored: dict) -> None:
    issue = _by_id(scored, "VRF-XSS-01")
    assert issue["verdict"] != "confirmed"
    assert issue["records"][0]["source"] == "hunt"
    assert issue["evidence"][0]["source"] == "hunt"
    assert len(issue["evidence"][0]["sha256"]) == 64


def test_extras_and_unknown_ids_do_not_expand_denominator(scored: dict) -> None:
    labels = {extra["label"] for extra in scored["extras"]}
    assert "F-extra-info" in labels
    assert "F-unknown-tag" in labels
    assert scored["unknown_ids"] == ["VRF-DOES-NOT-EXIST"]
    assert scored["rubric"]["expected"] == 5


def test_duplicate_issue_ids_fail_fast() -> None:
    with pytest.raises(verify_module.VerifyError, match="duplicate expected issue id"):
        verify_module.score_run(
            RUN_FIXTURE, FIXTURE_DIR / "duplicate-profile.yaml"
        )


def test_no_findings_marks_missed_and_deferred(tmp_path: Path) -> None:
    result = verify_module.score_run(tmp_path, PROFILE)
    assert result["rubric"]["confirmed"] == 0
    assert result["rubric"]["needs_validation"] == 0
    assert result["rubric"]["rejected"] == 0
    assert result["rubric"]["coverage"] == {
        "covered": 0,
        "partial": 0,
        "missed": 4,
        "deferred": 1,
        "ratio": 0.0,
    }
    assert len(result["gaps"]) == 5


def test_exploit_confirmed_without_embedded_evidence_is_downgraded(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "exploit" / "VRF-SQLI-01.json",
        {
            "check": "VRF-SQLI-01",
            "action": "sql_injection",
            "status": "confirmed",
            "proof": True,
            "evidence": [],
        },
    )
    result = verify_module.score_run(tmp_path, PROFILE)
    issue = _by_id(result, "VRF-SQLI-01")
    assert issue["verdict"] == "needs_validation"
    assert any("downgraded" in note for note in issue["notes"])


def test_verified_findings_downgrade_and_preserve_source(tmp_path: Path) -> None:
    root = tmp_path / "verify-test"
    shutil.copytree(RUN_FIXTURE, root)
    before = sha256((root / "findings.json").read_bytes()).hexdigest()
    result = verify_module.score_run(root, PROFILE)
    document, _ = verify_module.load_findings(root)
    verified = verify_module.build_verified_findings(document, result, root)
    verify_module.write_outputs(result, root, verified)

    assert sha256((root / "findings.json").read_bytes()).hexdigest() == before
    statuses = {item["id"]: item["status"] for item in verified["findings"]}
    assert statuses["F-sqli-confirmed"] == "confirmed"
    assert statuses["F-cmdi-missing-evidence"] == "needs_validation"
    assert statuses["F-extra-info"] == "needs_validation"
    tags = {item["id"]: item["tags"] for item in verified["findings"]}
    assert "rubric:VRF-SQLI-01" in tags["F-sqli-confirmed"]
    assert "rubric:extra" in tags["F-extra-info"]
    for name in ("verify.json", "VERIFICATION.md", "verified-findings.json"):
        assert (root / name).is_file()
    markdown = (root / "VERIFICATION.md").read_text(encoding="utf-8")
    assert "all intended issues" in markdown.lower() or "All 5 intended issues" in markdown
    assert "not a claim that every possible issue was found" in markdown
    assert "Coverage — deferred | 1" in markdown


def test_cli_json_contract(capsys: pytest.CaptureFixture[str]) -> None:
    from sak.__main__ import main

    exit_code = main(
        [
            "verify",
            "--run",
            str(CLI_RUN_DIR),
            "--profile",
            str(PROFILE),
            "--json",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 0
    payload = json.loads(captured.out)
    assert payload["schema"] == verify_module.SCHEMA
    assert payload["rubric"]["expected"] == 5
    assert payload["statement"]["possible_issues"].startswith("This is not a claim")
    assert (CLI_RUN_DIR / "verify.json").is_file()
    assert (CLI_RUN_DIR / "VERIFICATION.md").is_file()


def test_human_output_names_gaps(scored: dict) -> None:
    markdown = verify_module.render_verification(scored)
    assert "`VRF-IDOR-01`" in markdown
    assert "`VRF-UPLOAD-01`" in markdown
    assert "second principal received 403" in markdown
