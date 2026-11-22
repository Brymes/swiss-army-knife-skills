"""Offline contract tests for the black-box pilot operator document.

No network, Docker, browser or target source: the test reads the pilot document and
checks the required sections, commands, targets, evidence paths and secret hygiene.
"""

from __future__ import annotations

import re
from pathlib import Path

DOC = Path(__file__).resolve().parents[1] / "docs" / "blackbox-pilot.md"

REQUIRED_SECTIONS = (
    "## 1. What \"break into\" means here",
    "## 2. Prerequisites",
    "## 3. Kali WSL path",
    "## 4. Mac SSH-tunnel path",
    "## 5. DVWA setup",
    "## 6. Exact command matrix",
    "## 7. Evidence to expect",
    "## 8. What was proven",
    "## 9. Missed, deferred or qualified",
    "## 10. Cleanup and retention",
    "## 11. Honesty statement",
)

REQUIRED_COMMANDS = (
    "sak exploit",
    "sak verify",
    "sak report",
    "sak hunt",
)

SECRET_PATTERNS = {
    "serialized JWT": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    "vuln-bank merchant key": re.compile(r"\bvk_[A-Za-z0-9]{8,}\b"),
    "openai-style key": re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),
    "github token": re.compile(r"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}\b"),
    "aws access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "embedded credential": re.compile(r"\b(?:admin|root):[^\s`'\"]+"),
}


def test_pilot_doc_exists_and_has_required_sections() -> None:
    assert DOC.is_file(), f"missing {DOC}"
    text = DOC.read_text(encoding="utf-8")
    for section in REQUIRED_SECTIONS:
        assert section in text, f"missing section: {section}"


def test_pilot_doc_names_both_targets_and_commands() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "vuln-bank" in text
    assert "DVWA" in text
    assert "runs/blackbox-vuln-bank-final" in text
    assert "runs/blackbox-dvwa-final" in text
    assert "127.0.0.1:15000" in text
    assert "127.0.0.1:5000" in text
    assert "127.0.0.1:8080" in text
    for command in REQUIRED_COMMANDS:
        assert command in text, f"missing command: {command}"


def test_pilot_doc_states_the_rubric_boundary_and_results() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "15/15" in text
    assert "11/11" in text
    assert "not a claim that every possible vulnerability" in text
    assert "rubric" in text.lower()
    assert "needs_validation" in text
    assert "deferred" in text.lower()


def test_pilot_doc_has_no_embedded_secrets_or_non_loopback_urls() -> None:
    text = DOC.read_text(encoding="utf-8")
    for label, pattern in SECRET_PATTERNS.items():
        match = pattern.search(text)
        assert match is None, f"pilot doc contains a {label}: {match.group(0)[:12]}…"

    urls = re.findall(r"https?://[^\s)`'\"]+", text)
    assert urls, "the pilot doc should show the loopback commands"
    for url in urls:
        host = re.sub(r"^https?://", "", url).split("/", 1)[0].split(":", 1)[0]
        assert host in {"127.0.0.1", "localhost"}, f"non-loopback URL in pilot doc: {url}"


def test_pilot_doc_does_not_claim_unqualified_total_coverage() -> None:
    text = DOC.read_text(encoding="utf-8").lower()
    assert "all vulnerabilities" not in text
    assert "every possible vulnerability" in text
    assert "denominator" in text
