"""Offline contract tests for the public open-source packaging.

No network, GitHub API or live target. The tests read the public docs, CI files and
benchmark records, and assert the install/harness/Kali-MCP contract stays intact.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
AGENTS = ROOT / "AGENTS.md"
CONTRIBUTING = ROOT / "CONTRIBUTING.md"
SECURITY = ROOT / "SECURITY.md"
CONDUCT = ROOT / "CODE_OF_CONDUCT.md"
CHANGELOG = ROOT / "CHANGELOG.md"
HARNESS = ROOT / "docs" / "harness-integration.md"
KALI_MCP = ROOT / "docs" / "kali-mcp.md"
PUBLISHING = ROOT / "docs" / "publishing.md"
SKILL_USAGE = ROOT / "docs" / "skill-usage.md"
CI = ROOT / ".github" / "workflows" / "ci.yml"
ISSUES = ROOT / ".github" / "ISSUE_TEMPLATE"
PR_TEMPLATE = ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md"
GITIGNORE = ROOT / ".gitignore"
PYPROJECT = ROOT / "pyproject.toml"

PUBLIC_DOCS = (
    README,
    AGENTS,
    CONTRIBUTING,
    SECURITY,
    CONDUCT,
    CHANGELOG,
    HARNESS,
    KALI_MCP,
    SKILL_USAGE,
    PUBLISHING,
)

PII_PATTERNS = {
    "absolute macOS user path": re.compile(r"/Users/[A-Za-z0-9._-]+"),
    "absolute Windows user path": re.compile(r"C:\\\\Users\\\\"),
    "internal pack path": re.compile(r"\.durable-pack"),
    "internal agent pack": re.compile(r"\.agent-workpacks"),
    "serialized JWT": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    "vuln-bank merchant key": re.compile(r"\bvk_[A-Za-z0-9]{8,}\b"),
    "openai-style key": re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),
    "lab default password": re.compile(r"\b(?:admin123|SakLab[AB]123!|bookstore123)\b"),
    "env secret": re.compile(r"\b(?:VbProd_2026|VulnBankAdmin_2025|VbRedis_2026|ds_live_[A-Za-z0-9]+)\b"),
}


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_public_files_exist() -> None:
    for path in (*PUBLIC_DOCS, CI, PR_TEMPLATE, GITIGNORE, PYPROJECT):
        assert path.is_file(), f"missing public file: {path}"
    assert not (ROOT / ".durable-pack").exists(), "internal pack directory is in the public tree"
    assert not (ROOT / ".agent-workpacks").exists(), "internal agent pack is in the public tree"
    assert (ROOT / "benchmarks" / "vuln-bank.json").is_file()
    assert (ROOT / "benchmarks" / "dvwa-low.json").is_file()


def test_readme_links_the_public_guides() -> None:
    text = read(README)
    for token in (
        "docs/quickstart.md",
        "docs/skill-usage.md",
        "docs/harness-integration.md",
        "docs/kali-mcp.md",
        "docs/benchmark.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "docs/publishing.md",
    ):
        assert token in text, f"README is missing link: {token}"
    assert "github.com/Brymes/swiss-army-knife-skills" in text
    assert "Use your own harness and model" in text


def test_install_and_harness_contract() -> None:
    usage = read(SKILL_USAGE)
    harness = read(HARNESS)
    for token in ("sh install.sh --local", "sh install.sh --global", ".opencode/skills"):
        assert token in usage
    for token in (
        "OpenCode",
        "Claude Code",
        "Codex",
        "--model",
        "--runner",
        "NEAR_AI_API_KEY",
        "Kali MCP",
        "no MCP",
    ):
        assert token in harness, f"harness guide is missing: {token}"
    assert "sak plan" in harness
    assert "sak exploit" in harness
    assert "sak verify" in harness
    assert "sak report" in harness


def test_kali_mcp_guide_covers_both_modes_and_safety() -> None:
    text = read(KALI_MCP)
    for token in (
        "optional",
        "No MCP",
        "Kali WSL",
        "SSH tunnel",
        "exec",
        "workspace",
        "scope.md",
        "uv run sak",
        "mask",
        "root",
    ):
        assert token in text, f"Kali MCP guide is missing: {token}"
    assert "does **not** ship" in text or "does not ship" in text


def test_contributing_security_and_ci_contract() -> None:
    contributing = read(CONTRIBUTING)
    security = read(SECURITY)
    ci = yaml.safe_load(read(CI))
    assert "uv run pytest -q" in contributing
    assert "uv run sak catalog validate" in contributing
    assert "SECURITY.md" in contributing
    assert "private GitHub security advisory" in security
    assert "security/advisories/new" in security
    assert "permissions" in ci
    assert ci["jobs"]["test"]["runs-on"] == "ubuntu-latest"
    steps = ci["jobs"]["test"]["steps"]
    commands = "\n".join(str(step.get("run", "")) for step in steps)
    assert "uv sync" in commands
    assert "uv run pytest" in commands
    assert "uv run sak catalog validate" in commands


def test_issue_templates_are_valid_yaml() -> None:
    for path in sorted(ISSUES.glob("*.yml")):
        yaml.safe_load(read(path))
    assert (ISSUES / "config.yml").is_file()


def test_public_tree_has_no_pii_or_secret_markers() -> None:
    scanned = (*[path for path in PUBLIC_DOCS if path != PUBLISHING], ROOT / "benchmarks" / "README.md")
    for path in scanned:
        text = read(path)
        for label, pattern in PII_PATTERNS.items():
            match = pattern.search(text)
            assert match is None, f"{path} contains a {label}: {match.group(0)[:24]}"


def test_gitignore_keeps_internal_artifacts_out() -> None:
    text = read(GITIGNORE)
    for path in (".durable-pack/", ".agent-workpacks/", "worktrees/", "tests/fixtures/verify/", ".opencode/"):
        assert path in text, f".gitignore is missing {path}"


def test_pyproject_declares_the_public_repository() -> None:
    text = read(PYPROJECT)
    assert "https://github.com/Brymes/swiss-army-knife-skills" in text
    assert "Homepage" in text
    assert "Issues" in text


def test_changelog_and_benchmark_are_honest() -> None:
    changelog = read(CHANGELOG)
    benchmark = read(ROOT / "docs" / "benchmark.md")
    assert "0.1.0" in changelog
    assert "15/15" in benchmark
    assert "11/11" in benchmark
    assert "not a claim that every possible vulnerability" in " ".join(benchmark.split())
    record = json.loads(read(ROOT / "benchmarks" / "vuln-bank.json"))
    assert record["schema"] == "sak.skill.benchmark.v1"
    assert record["rubric"]["expected"] == 15
    assert record["rubric"]["confirmed"] == 15


def test_publishing_guide_contains_the_pii_scan() -> None:
    text = read(PUBLISHING)
    for token in ("/Users/", ".durable-pack", "git grep", "gh repo create", "public-release:main"):
        assert token in text, f"publishing guide is missing: {token}"
