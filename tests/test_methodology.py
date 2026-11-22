"""Checks for the T7 methodology notes and improvement-loop rubric.

These tests are offline by design: they only read files in the repository. No network
call, browser or subprocess is used.
"""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
METHOD = ROOT / "knowledge" / "methodology"
BOOK = METHOD / "harness-engineering.md"
MAP = METHOD / "sak-harness-map.md"
CI = METHOD / "ci-pentest-harness.md"
LOOP = ROOT / "docs" / "improvement-loop.md"

BOOK_URL = "https://grahamhelton.github.io/harness-engineering-workshop-book/print.html"
CI_URL = "https://zenn.dev/team_zenn/articles/opencode-docker-actions-ai-pentest"

REQUIRED_FILES = [BOOK, MAP, CI, LOOP]

METRICS = [
    "seeded-issue recall",
    "confirmed precision",
    "trust-boundary coverage",
    "time to first signal",
    "cost per finding",
    "duplicate rate",
    "false-positive rate",
]


def read(path: Path) -> str:
    assert path.is_file(), f"missing required file: {path.relative_to(ROOT)}"
    return path.read_text(encoding="utf-8")


def test_required_files_exist_and_are_not_empty():
    for path in REQUIRED_FILES:
        text = read(path)
        assert len(text) > 500, f"{path.relative_to(ROOT)} looks like a stub"


def test_book_notes_are_attributed():
    text = read(BOOK)
    assert BOOK_URL in text
    assert "Graham Helton" in text
    assert "Ryan Basden" in text
    assert "2026-11-11" in text
    lowered = text.lower()
    assert "own words" in lowered or "summary" in lowered
    assert "not a copy" in lowered or "not a substitute" in lowered


def test_book_notes_have_required_sections():
    text = read(BOOK)
    required = [
        "## What the book argues",
        "## Problems the book names",
        "## Components",
        "## Claims and evidence status",
        "## Exercises",
        "## Limits and applicability",
    ]
    for heading in required:
        assert heading in text, f"missing heading: {heading}"


def test_book_notes_cover_every_component():
    text = read(BOOK).lower()
    components = [
        "local validation environment",
        "research state",
        "context management",
        "external integrations",
        "operational interfaces",
        "telemetry",
        "skills",
        "deterministic tools",
        "hooks",
        "oracles",
        "reporting and disclosure",
    ]
    missing = [name for name in components if name not in text]
    assert not missing, f"book notes miss components: {missing}"


def test_book_notes_are_a_summary_not_a_full_book_dump():
    text = read(BOOK)
    words = text.split()
    # A useful summary is short. The book's print page is far larger than this bound.
    assert len(words) < 4000, f"book notes look like a dump ({len(words)} words)"
    assert len(text.splitlines()) < 400
    assert max(len(line) for line in text.splitlines()) < 1500
    # Canaries from the book that should not appear in a paraphrase.
    assert "You did not train the models you use for research." not in text
    assert "Press \u2190 or \u2192 to navigate between chapters" not in text
    assert "Keyboard shortcuts" not in text


def test_mapping_covers_components_and_states():
    text = read(MAP)
    lowered = text.lower()
    for state in ("designed", "partial", "deferred"):
        assert state in lowered, f"mapping does not use status: {state}"
    for term in (
        "claim/evidence discipline",
        "local validation environment",
        "external integrations",
        "operational interfaces",
        "memory / research state",
        "context management",
        "telemetry",
        "skills",
        "deterministic tools",
        "hooks",
        "oracles",
        "reporting / disclosure",
    ):
        assert term in lowered, f"mapping misses: {term}"
    for name in ("sak plan", "sak run", "sak report", "sak doctor"):
        assert name in lowered, f"mapping does not name {name}"
    for artifact in ("findings.json", "coverage-ledger.json", "state.json"):
        assert artifact in lowered, f"mapping does not name {artifact}"


def test_ci_note_is_attributed_and_summarised():
    text = read(CI)
    assert CI_URL in text
    assert "dyoshikawa" in text
    assert "Zenn" in text
    assert "2026-11-04" in text
    assert "2026-11-11" in text
    lowered = text.lower()
    assert "summary" in lowered
    assert "not a translation" in lowered or "our own english summary" in lowered


def test_ci_note_covers_the_harness_parts():
    lowered = read(CI).lower()
    for term in (
        "github actions",
        "docker",
        "network namespace",
        "iptables",
        "opencode",
        "curl",
        "nuclei",
        "zap",
        "playwright",
        "ai gateway",
        "classifier",
        "emulator",
    ):
        assert term in lowered, f"CI note misses: {term}"


def test_ci_note_maps_to_a_future_sak_ci_mode_only():
    text = read(CI)
    lowered = text.lower()
    assert "sak ci" in lowered
    assert "not built in v1" in lowered
    assert "deferred" in lowered
    assert "scope.md" in lowered
    assert "deny" in lowered


def test_improvement_loop_lists_every_metric():
    lowered = read(LOOP).lower()
    missing = [name for name in METRICS if name not in lowered]
    assert not missing, f"improvement loop misses metrics: {missing}"
    assert "false-positive" in lowered


def test_improvement_loop_has_required_sections():
    text = read(LOOP)
    required = [
        "## Eval set and ground truth",
        "## Metrics",
        "## Measurement protocol",
        "## Update loop",
        "## Evidence standard",
        "## Anti-pattern checklist",
        "## Reporting a loop result",
    ]
    for heading in required:
        assert heading in text, f"missing heading: {heading}"


def test_update_loop_has_all_six_steps():
    text = read(LOOP)
    for step in (
        "### 1. Run",
        "### 2. Triage",
        "### 3. Classify misses",
        "### 4. Change one variable",
        "### 5. Rerun",
        "### 6. Record the delta",
    ):
        assert step in text, f"missing update-loop step: {step}"


def test_evidence_standard_defines_what_counts():
    lowered = read(LOOP).lower()
    for term in ("reproduction", "source trace", "observed result"):
        assert term in lowered, f"evidence standard misses: {term}"
    assert "every claim names its evidence path" in lowered
    assert "stale evidence is not evidence" in lowered
    assert "unresolved evidence is not coverage" in lowered
    assert "needs_validation" in lowered


def test_anti_pattern_checklist_is_complete():
    text = read(LOOP)
    for phrase in (
        "Unbounded exploration",
        "No coverage ledger",
        "Treating a model claim as proof",
        "Duplicate root causes",
        "Severity inflation",
        "Live-target drift",
        "Unreviewed prompt changes",
    ):
        assert phrase in text, f"anti-pattern checklist misses: {phrase}"


def test_tests_do_not_import_network_clients():
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    forbidden = {"requests", "httpx", "urllib", "socket", "http", "aiohttp", "urllib3"}
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not imported & forbidden, f"network import found: {imported & forbidden}"
