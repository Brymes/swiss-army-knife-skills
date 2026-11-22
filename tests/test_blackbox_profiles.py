"""Offline contract tests for the black-box target profiles and rubrics.

No network, Docker or browser execution: every test reads the profile, checks and doc
files, or parses YAML/JSON. The profiles must stay parseable without target source.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
DVWA = REPO_ROOT / "targets" / "dvwa" / "blackbox"
VULN_BANK = REPO_ROOT / "targets" / "vuln-bank" / "blackbox"
DOC = REPO_ROOT / "docs" / "blackbox-targets.md"

PROFILES = {
    "dvwa": DVWA / "profile.yaml",
    "vuln-bank": VULN_BANK / "profile.yaml",
}
CHECKS = {
    "dvwa": DVWA / "checks.json",
    "vuln-bank": VULN_BANK / "checks.json",
}

DVWA_CLASSES = {
    "sql-injection",
    "command-injection",
    "unrestricted-upload",
    "xss-reflected",
    "xss-stored",
    "csrf",
    "file-inclusion",
    "brute-force",
    "session-management",
    "csp-bypass",
    "captcha-bypass",
}

VB_CLASSES = {
    "authentication",
    "idor",
    "authorization",
    "business-logic",
    "xss-stored",
    "sql-injection",
    "admin-privilege",
}

# Documented lab-only demo defaults. The profiles may name these; real secrets may not appear.
LAB_PASSWORDS = {
    "password",
    "admin123",
    "bookstore123",
    "pwnshop123",
    "zerohealth123",
    "SakLabA123!",
    "SakLabB123!",
}

# Markers of target source or a local source checkout. A profile must not depend on these.
SOURCE_PATH_MARKERS = (
    "/Users/",
    "vendor/external",
    "src/sak/",
    "app.py",
    "database.py",
    "models.py",
    "requirements.txt",
    "Dockerfile",
    "docker-compose.yml",
)

SECRET_PATTERNS = {
    "openai-style key": re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),
    "github token": re.compile(r"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}\b"),
    "aws access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "vuln-bank merchant key": re.compile(r"\bvk_[A-Za-z0-9]{8,}\b"),
    "slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "serialized jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
}


def load_yaml(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{path} must parse to a mapping"
    return data


def load_json(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{path} must parse to an object"
    return data


def all_documents() -> list:
    paths = [*PROFILES.values(), *CHECKS.values(), DOC]
    return [
        pytest.param(path, path.read_text(encoding="utf-8"), id=path.name)
        for path in paths
    ]


# --- parse and shape ----------------------------------------------------------


@pytest.mark.parametrize("target", sorted(PROFILES))
def test_profile_and_checks_parse(target: str) -> None:
    profile = load_yaml(PROFILES[target])
    checks = load_json(CHECKS[target])

    assert profile["schema"] == "sak.blackbox.profile.v1"
    assert checks["schema"] == "sak.blackbox.checks.v1"
    assert profile["target"]["id"] == target
    assert checks["target"] == target
    assert checks["profile"] == f"targets/{target}/blackbox/profile.yaml"


@pytest.mark.parametrize("target", sorted(PROFILES))
def test_required_auth_scope_and_budget_fields(target: str) -> None:
    profile = load_yaml(PROFILES[target])

    target_block = profile["target"]
    assert target_block["base_url"].startswith("http://127.0.0.1:")
    assert target_block["authorized"] is True

    accounts = profile["accounts"]
    assert accounts, f"{target} needs at least one lab account"
    for account in accounts:
        assert account["id"] and account["role"] and account["username"]
        assert account.get("password_env"), f"{account['id']} needs a password env override"
        assert account.get("lab_default") in LAB_PASSWORDS, (
            f"{account['id']} must name a documented lab default"
        )

    auth = profile["auth"]
    login = auth["login"]
    assert login["method"] in {"GET", "POST"}
    assert login["path"].startswith("/")
    assert login["fields"], f"{target} login fields are required"
    assert isinstance(auth["csrf"]["required"], bool)
    assert auth["session"]["type"]
    assert auth["session"]["jar_env"]

    scope = profile["scope"]
    assert scope["allowed_hosts"], f"{target} needs explicit allowed hosts"
    assert scope["out_of_scope"]
    assert scope["requires_scope_file"] is True
    for host in scope["allowed_hosts"]:
        assert host.startswith(("127.0.0.1:", "localhost:")), (
            f"{target} allows a non-loopback host: {host}"
        )

    budget = profile["budget"]
    for key in (
        "max_requests",
        "max_seconds",
        "max_agents",
        "max_concurrency",
        "waves",
        "stop_after_waves_without_signal",
        "per_check_timeout_seconds",
    ):
        assert isinstance(budget[key], int) and budget[key] > 0, f"{target} budget.{key}"
    assert budget["max_requests"] <= 1000
    assert budget["max_seconds"] <= 3600

    safety = profile["safety"]
    assert safety["intrusive_requires_approval"] is True
    assert safety["destructive_default"] is False
    assert safety["denial_of_service"] is False
    assert safety["brute_force_default"] is False
    assert safety["cleanup_only_lab_created_objects"] is True


@pytest.mark.parametrize("target", sorted(PROFILES))
def test_expected_issues_have_the_contract_fields(target: str) -> None:
    profile = load_yaml(PROFILES[target])
    expected = profile["expected"]
    assert expected, f"{target} needs an expected-issue rubric"

    severities = {"low", "medium", "high", "critical"}
    for issue in expected:
        assert issue["id"].startswith(("DVWA-", "VB-"))
        for key in ("title", "class", "endpoint", "proof", "severity", "evidence", "cleanup"):
            assert issue.get(key), f"{issue['id']} is missing {key}"
        assert "intrusive" in issue and isinstance(issue["intrusive"], bool), (
            f"{issue['id']} is missing a boolean intrusive flag"
        )
        assert "destructive" in issue and isinstance(issue["destructive"], bool), (
            f"{issue['id']} is missing a boolean destructive flag"
        )
        assert issue["severity"] in severities
        assert issue["approval"] in {"none", "profile", "owner"}
        assert len(issue["proof"]) >= 30, f"{issue['id']} proof is too vague"
        assert isinstance(issue["evidence"], list) and issue["evidence"]
        if issue["intrusive"]:
            assert issue["approval"] in {"profile", "owner"}, (
                f"{issue['id']} is intrusive and needs explicit approval"
            )


@pytest.mark.parametrize("target", sorted(PROFILES))
def test_issue_ids_are_unique_across_rubric_and_checks(target: str) -> None:
    profile = load_yaml(PROFILES[target])
    checks = load_json(CHECKS[target])

    expected_ids = [issue["id"] for issue in profile["expected"]]
    check_ids = [check["issue_id"] for check in checks["checks"]]
    assert len(expected_ids) == len(set(expected_ids)), f"{target} duplicates expected ids"
    assert len(check_ids) == len(set(check_ids)), f"{target} duplicates check issue ids"
    assert set(expected_ids) == set(check_ids), (
        f"{target} rubric and checks disagree: "
        f"{sorted(set(expected_ids) ^ set(check_ids))}"
    )


# --- required issue classes ---------------------------------------------------


@pytest.mark.parametrize(
    ("target", "required"),
    [("dvwa", DVWA_CLASSES), ("vuln-bank", VB_CLASSES)],
)
def test_required_issue_classes_are_present(target: str, required: set[str]) -> None:
    profile = load_yaml(PROFILES[target])
    classes = {issue["class"] for issue in profile["expected"]}
    missing = required - classes
    assert not missing, f"{target} rubric is missing classes: {sorted(missing)}"


def test_dvwa_rubric_covers_the_low_security_page_set() -> None:
    profile = load_yaml(PROFILES["dvwa"])
    ids = {issue["id"] for issue in profile["expected"]}
    assert {
        "DVWA-SQLI-01",
        "DVWA-CMDI-01",
        "DVWA-UPLOAD-01",
        "DVWA-XSS-R-01",
        "DVWA-XSS-S-01",
        "DVWA-CSRF-01",
        "DVWA-FI-01",
        "DVWA-BRUTE-01",
        "DVWA-SESSION-01",
        "DVWA-CSP-01",
        "DVWA-CAPTCHA-01",
    } == ids


def test_brute_force_is_disabled_and_owner_approved() -> None:
    profile = load_yaml(PROFILES["dvwa"])
    brute = next(issue for issue in profile["expected"] if issue["id"] == "DVWA-BRUTE-01")
    assert brute["default"] is False
    assert brute["approval"] == "owner"
    assert brute["intrusive"] is True
    assert "DVWA-BRUTE-01" in profile["safety"]["owner_approval_required_for"]


# --- check sequences ----------------------------------------------------------


@pytest.mark.parametrize(
    ("target", "required_sequences"),
    [
        ("dvwa", {"login", "sql-injection", "command-execution", "upload-php-marker",
                  "xss-reflected", "xss-stored"}),
        ("vuln-bank", {"login", "token-extraction", "two-account-idor", "sqli-login",
                       "negative-transfer", "stored-xss"}),
    ],
)
def test_required_sequences_exist(target: str, required_sequences: set[str]) -> None:
    checks = load_json(CHECKS[target])
    sequences = checks["sequences"]
    missing = required_sequences - set(sequences)
    assert not missing, f"{target} checks are missing sequences: {sorted(missing)}"


@pytest.mark.parametrize("target", sorted(PROFILES))
def test_every_sequence_is_concrete_and_cleans_up(target: str) -> None:
    checks = load_json(CHECKS[target])
    sequences = checks["sequences"]

    for sequence_id, sequence in sequences.items():
        steps = sequence.get("steps") or []
        assert len(steps) >= 2, f"{sequence_id} needs at least a baseline and a proof step"
        assert sequence.get("expected_evidence"), f"{sequence_id} needs expected evidence"
        assert sequence.get("cleanup"), f"{sequence_id} needs a cleanup statement"
        for step in steps:
            assert step.get("n") and step.get("action"), f"{sequence_id} has an incomplete step"
            assert step.get("expect"), f"{sequence_id} step {step['n']} has no expected result"

    for check in checks["checks"]:
        assert check["sequence"] in sequences, (
            f"{check['issue_id']} references missing sequence {check['sequence']}"
        )
        assert check["kind"] in {"http", "browser"}
        assert isinstance(check["intrusive"], bool)
        assert check["approval"] in {"none", "profile", "owner"}

    used = {check["sequence"] for check in checks["checks"]}
    shared = {
        sequence_id
        for sequence_id, sequence in sequences.items()
        if sequence.get("shared") is True
    }
    assert used == set(sequences) - shared, (
        f"{target} has sequences without a check or checks without a sequence: "
        f"{sorted(used ^ (set(sequences) - shared))}"
    )


@pytest.mark.parametrize("target", sorted(PROFILES))
def test_checks_sanitize_tokens_and_use_loopback_placeholders(target: str) -> None:
    checks = load_json(CHECKS[target])
    variables = checks["variables"]
    base = variables["base_url"]
    assert base["default"].startswith("http://127.0.0.1:")
    assert base["loopback_only"] is True
    assert checks["control"]["sanitize"], f"{target} must declare masking rules"

    dump = json.dumps(checks)
    assert "${" in dump, "sequences should use variables rather than hard-coded accounts"
    for token in ("Bearer ${token}", "Bearer ${tester"):
        assert token in dump or target == "dvwa"


# --- secrets and source independence -----------------------------------------


@pytest.mark.parametrize("path,text", all_documents())
def test_no_source_paths_or_vendored_target_code(path: Path, text: str) -> None:
    for marker in SOURCE_PATH_MARKERS:
        assert marker not in text, f"{path} references a target source path: {marker}"


@pytest.mark.parametrize("path,text", all_documents())
def test_no_embedded_real_secrets(path: Path, text: str) -> None:
    for label, pattern in SECRET_PATTERNS.items():
        match = pattern.search(text)
        assert match is None, f"{path} contains a {label}: {match.group(0)[:12]}…"
    assert "DEEPSEEK_API_KEY=" not in text
    assert re.search(r"Authorization: Bearer (?!<|\$\{)[A-Za-z0-9]", text) is None, (
        "only a <token> or ${token} placeholder may appear after Authorization: Bearer"
    )


def test_profiles_name_only_documented_lab_defaults() -> None:
    for profile_path in PROFILES.values():
        text = profile_path.read_text(encoding="utf-8")
        for password in LAB_PASSWORDS:
            if password in text:
                assert "lab_default" in text, (
                    f"{profile_path} names {password!r} without a lab_default context"
                )


# --- docs and scope -----------------------------------------------------------


def test_docs_cover_the_operator_paths_and_the_rubric_denominator() -> None:
    text = DOC.read_text(encoding="utf-8")
    for required in (
        "targets/dvwa/blackbox/profile.yaml",
        "targets/vuln-bank/blackbox/profile.yaml",
        "Kali",
        "Mac",
        "ssh -N -L",
        "Scope and budget",
        "Expected-vulnerability rubric",
        "Why “all vulnerabilities” means the rubric",
        "DVWA-SQLI-01",
        "VB-BOLA-01",
        "admin123",
        "ADMIN001",
        "bookstore@vulnbank.org",
    ):
        assert required in text, f"{DOC} is missing: {required}"


def test_docs_explain_rubric_not_literal_all_vulnerabilities() -> None:
    text = DOC.read_text(encoding="utf-8").lower()
    assert "not a literal claim" in text
    assert "denominator" in text
    assert "confirmed" in text and "needs_validation" in text and "rejected" in text
