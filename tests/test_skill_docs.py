"""Offline contract tests for the installed-skill usage guide and benchmark.

These tests read Markdown and JSON only. They do not start OpenCode, a container, a
tunnel or a target. If the live run directories are present, the benchmark records
are compared with their verification and findings documents.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
USAGE = ROOT / "docs" / "skill-usage.md"
BENCHMARK_DOC = ROOT / "docs" / "benchmark.md"
BENCHMARK_README = ROOT / "benchmarks" / "README.md"
README = ROOT / "README.md"
SKILL = ROOT / "skills" / "swiss-army-knife" / "SKILL.md"
BENCHMARKS = {
    "vuln-bank": ROOT / "benchmarks" / "vuln-bank.json",
    "dvwa-low": ROOT / "benchmarks" / "dvwa-low.json",
}

SECRET_PATTERNS = {
    "serialized JWT": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    "vuln-bank merchant key": re.compile(r"\bvk_[A-Za-z0-9]{8,}\b"),
    "openai-style key": re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),
    "github token": re.compile(r"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}\b"),
    "aws access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "lab default password": re.compile(r"\b(?:admin123|SakLab[AB]123!|bookstore123)\b"),
    "env secret": re.compile(r"\b(?:VbProd_2026|VulnBankAdmin_2025|VbRedis_2026|ds_live_[A-Za-z0-9]+)\b"),
    "session cookie": re.compile(r"\bPHPSESSID=[A-Za-z0-9]{8,}\b"),
}

REQUIRED_USAGE = (
    "sh install.sh --dry-run",
    "sh install.sh --local",
    ".opencode/skills",
    "swiss-army-knife",
    "scope.md",
    "sak plan",
    "sak hunt",
    "sak exploit",
    "sak verify",
    "sak report",
    "docs/benchmark.md",
    "sak doctor",
    "127.0.0.1:15000",
)

REQUIRED_BENCHMARK = (
    "vuln-bank",
    "DVWA Low",
    "15/15",
    "11/11",
    "sak verify",
    "sak report",
    "denominator",
    "not a claim",
    "needs_validation",
    "runs/blackbox-vuln-bank-final",
    "runs/blackbox-dvwa-final",
    "127.0.0.1:15000",
    "127.0.0.1:8080",
)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_documentation_and_benchmark_files_exist() -> None:
    for path in (USAGE, BENCHMARK_DOC, BENCHMARK_README, SKILL, *BENCHMARKS.values()):
        assert path.is_file(), f"missing {path}"


def test_skill_entry_point_is_installable() -> None:
    text = read(SKILL)
    frontmatter = text.split("---", 2)[1]
    data = yaml.safe_load(frontmatter)
    assert data["name"] == "swiss-army-knife"
    assert "license: MIT" in text
    assert "Opering contract" not in text  # keep the public entry point typo-free
    assert "Operating contract" in text


def test_usage_guide_has_install_and_command_contract() -> None:
    text = read(USAGE)
    for token in REQUIRED_USAGE:
        assert token in text, f"usage guide is missing: {token}"
    assert "OpenCode" in text
    assert "No scope, no action" in text
    assert "Evidence or it did not happen" in text
    assert "restart" in text.lower()


def test_benchmark_doc_states_results_and_caveats() -> None:
    text = read(BENCHMARK_DOC)
    for token in REQUIRED_BENCHMARK:
        assert token in text, f"benchmark doc is missing: {token}"
    assert "Hunt candidates" in text or "hunt candidates" in text
    assert "The full operator sequence" in text or "blackbox-pilot.md" in text
    assert "does not mean the application has no other bugs" in text


def test_readme_links_the_new_docs() -> None:
    text = read(README)
    assert "docs/skill-usage.md" in text
    assert "docs/benchmark.md" in text
    assert "benchmarks/" in text
    assert "swiss-army-knife" in text


@pytest.mark.parametrize("target", sorted(BENCHMARKS))
def test_benchmark_record_shape_and_counts(target: str) -> None:
    record = json.loads(read(BENCHMARKS[target]))
    assert record["schema"] == "sak.skill.benchmark.v1"
    assert record["benchmark"] == "dummy-target-rubric-v1"
    assert record["target"] == target
    assert record["target_url"].startswith("http://127.0.0.1:")
    assert Path(record["profile"]).is_file()

    rubric = record["rubric"]
    assert rubric["expected"] >= 1
    assert rubric["confirmed"] == rubric["expected"]
    assert rubric["needs_validation"] == 0
    assert rubric["rejected"] == 0
    assert rubric["coverage"]["covered"] == rubric["expected"]
    assert rubric["coverage"]["partial"] == 0
    assert rubric["coverage"]["missed"] == 0
    assert rubric["coverage"]["deferred"] == 0
    assert rubric["coverage"]["ratio"] == 1.0

    findings = record["findings"]
    assert len(findings) == rubric["confirmed"]
    issues = [item["issue"] for item in findings]
    assert len(set(issues)) == len(issues)
    for item in findings:
        assert item["status"] == "confirmed"
        assert item["artifact"].startswith("exploit/")
        assert item["artifact"].endswith(".json")
        assert re.fullmatch(r"[a-f0-9]{64}", item["evidence_sha256"])
        assert item["check"]
    assert record["checks"]["confirmed_artifacts"] >= rubric["confirmed"]
    assert record["checks"]["requests"] > 0
    for command in ("sak exploit", "sak verify", "sak report"):
        assert any(command in item for item in record["commands"])


def test_benchmark_records_and_docs_have_no_secrets() -> None:
    texts = [USAGE, BENCHMARK_DOC, BENCHMARK_README, *BENCHMARKS.values()]
    for path in texts:
        text = read(path)
        for label, pattern in SECRET_PATTERNS.items():
            match = pattern.search(text)
            assert match is None, f"{path} contains a {label}: {match.group(0)[:12]}…"


def test_benchmark_records_match_live_verification_when_present() -> None:
    for target, record_path in BENCHMARKS.items():
        record = json.loads(read(record_path))
        run_dir = ROOT / record["run_dir"]
        verify_path = run_dir / "verify.json"
        findings_path = run_dir / "findings.json"
        if not verify_path.is_file() or not findings_path.is_file():
            pytest.skip(f"live evidence for {target} is not present")
        verify = json.loads(read(verify_path))
        findings = json.loads(read(findings_path))
        assert verify["rubric"]["expected"] == record["rubric"]["expected"]
        assert verify["rubric"]["confirmed"] == record["rubric"]["confirmed"]
        assert verify["rubric"]["coverage"] == record["rubric"]["coverage"]
        assert sorted(item["id"] for item in findings["findings"]) == sorted(
            item["id"] for item in record["findings"]
        )
