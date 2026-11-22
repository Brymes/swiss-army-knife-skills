"""Manifest checks for the portable swiss-army-knife skill.

These tests are offline: they read files in the repository and parse the skill's
own Markdown. No network, no subprocess and no agent harness is required.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = ROOT / "skills" / "swiss-army-knife"
SKILL = SKILL_DIR / "SKILL.md"
REFERENCES = SKILL_DIR / "references"
ORCHESTRATION = ROOT / "docs" / "orchestration.md"

REFERENCE_SECTIONS = {
    "workflow.md": [
        "## Intake gate",
        "## Scope template",
        "## Threat-model template",
        "## Budget",
        "## Coverage ledger",
        "## Run directory",
    ],
    "selection.md": [
        "## Planning with the CLI",
        "## Roles",
        "## Verified-only auto-run",
        "## Execution routing",
        "## Manual fallback",
    ],
    "safety.md": [
        "## Authorization",
        "## Forbidden actions",
        "## Secrets and data",
        "## Rate and blast radius",
        "## Stop rules",
    ],
    "prompt-mutation.md": [
        "## Seed",
        "## Mutate",
        "## Hunt in parallel",
        "## Evidence contract",
        "## Signal classification",
        "## Stop and feed the next wave",
    ],
    "reporting.md": [
        "## Verification",
        "## Dedupe",
        "## Verdicts",
        "## Evidence requirements",
        "## Report artifacts",
        "## Learn",
    ],
    "sources.md": [
        "## Provenance",
        "## Command map",
        "## Licenses",
        "## Attribution",
    ],
}

SKILL_SECTIONS = [
    "## When to use",
    "## Operating contract",
    "## Workflow",
    "## Roles and budgets",
    "## Stop conditions",
    "## References",
]

ORCHESTRATION_SECTIONS = [
    "## Worked example: web black-box",
    "## Worked example: source audit",
    "## Worked example: binary triage",
    "## Shared checklist",
]

# Frozen CLI contract (C2) plus the T1 commands that already exist.
ALLOWED_SAK_COMMANDS = {
    "catalog",
    "doctor",
    "engine",
    "eval",
    "findings",
    "plan",
    "prompts",
    "report",
    "run",
}

PROMPT_ID_RANGES = {
    "INV": 13,
    "VIBE": 14,
    "SSRF": 8,
    "LLM": 8,
    "MUT": 1,
    "VER": 1,
    "REP": 1,
}

FRONTMATTER_KEYS = {"name", "description", "license"}
LINK = re.compile(r"!?\[[^\]]+\]\(([^)]+)\)")
SAK_COMMAND = re.compile(r"\bsak ([a-z][a-z-]*)")
PROMPT_ID = re.compile(r"\b(INV|VIBE|SSRF|LLM|MUT|VER|REP)-([0-9]{2})\b")


def read(path: Path) -> str:
    assert path.is_file(), f"missing required file: {path.relative_to(ROOT)}"
    return path.read_text(encoding="utf-8")


def split_frontmatter(text: str, path: Path) -> tuple[dict[str, object], str]:
    assert text.startswith("---\n"), f"{path.relative_to(ROOT)} must start with YAML frontmatter"
    end = text.find("\n---\n", 4)
    assert end != -1, f"{path.relative_to(ROOT)} has no closing frontmatter fence"
    header = text[4:end]
    body = text[end + len("\n---\n") :]
    data = yaml.safe_load(header)
    assert isinstance(data, dict), f"{path.relative_to(ROOT)} frontmatter is not a mapping"
    return data, body


def slug(heading: str) -> str:
    value = heading.strip().lower().replace("`", "")
    value = re.sub(r"[^\w\s-]", "", value, flags=re.UNICODE)
    return re.sub(r"[\s_]+", "-", value).strip("-")


def anchors(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    return {slug(match.group(1)) for match in re.finditer(r"^#{1,6} (.+)$", text, re.MULTILINE)}


def local_links(path: Path) -> list[tuple[str, str]]:
    """Return ``(target, anchor)`` for every relative Markdown link in *path*."""
    found: list[tuple[str, str]] = []
    for raw in LINK.findall(path.read_text(encoding="utf-8")):
        target = raw.strip()
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        target = target.split("#", 1)[0].strip()
        if not target:
            continue
        found.append((target, raw.strip()))
    return found


def skill_texts() -> list[Path]:
    return [SKILL, ORCHESTRATION, *sorted(REFERENCES.glob("*.md"))]


def test_frontmatter_is_valid_and_portable() -> None:
    text = read(SKILL)
    data, _ = split_frontmatter(text, SKILL)

    assert set(data) <= FRONTMATTER_KEYS, f"platform-specific frontmatter keys: {set(data) - FRONTMATTER_KEYS}"
    assert data["name"] == "swiss-army-knife"
    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", str(data["name"]))
    assert data["license"] == "MIT"

    description = str(data["description"])
    assert 80 <= len(description) <= 1024, "description must be useful but within the skill spec limit"
    normalized = description.lower().replace("-", " ")
    for trigger in ("security audit", "pentest", "bug bounty", "finding vulnerabilities", "security tools", "suite"):
        assert trigger in normalized, f"description does not trigger on {trigger!r}"


def test_skill_has_required_sections() -> None:
    body = split_frontmatter(read(SKILL), SKILL)[1]
    for heading in SKILL_SECTIONS:
        assert heading in body, f"SKILL.md is missing {heading!r}"
    assert "## Workflow" in body


@pytest.mark.parametrize("name", sorted(REFERENCE_SECTIONS))
def test_reference_exists_and_has_required_sections(name: str) -> None:
    text = read(REFERENCES / name)
    assert len(text) > 800, f"{name} looks like a stub"
    for heading in REFERENCE_SECTIONS[name]:
        assert heading in text, f"{name} is missing {heading!r}"


def test_all_references_are_linked_from_the_skill() -> None:
    linked = {(SKILL.parent / target).resolve() for target, _ in local_links(SKILL)}
    for path in sorted(REFERENCES.glob("*.md")):
        assert path.resolve() in linked, f"{path.relative_to(ROOT)} is not linked from SKILL.md"
    assert ORCHESTRATION.resolve() in linked, "docs/orchestration.md is not linked from SKILL.md"


def test_orchestration_has_three_worked_examples() -> None:
    text = read(ORCHESTRATION)
    assert len(text) > 2000, "orchestration.md looks like a stub"
    for heading in ORCHESTRATION_SECTIONS:
        assert heading in text, f"orchestration.md is missing {heading!r}"


def test_local_links_resolve() -> None:
    for path in skill_texts():
        for target, raw in local_links(path):
            resolved = (path.parent / target).resolve()
            assert resolved.exists(), f"{path.relative_to(ROOT)} links to missing {raw!r}"
            if "#" in raw:
                anchor = raw.split("#", 1)[1]
                if anchor and resolved.suffix == ".md":
                    assert anchor in anchors(resolved), (
                        f"{path.relative_to(ROOT)} links to missing anchor #{anchor} in {resolved.name}"
                    )


def test_only_contract_commands_are_named() -> None:
    for path in skill_texts():
        for command in SAK_COMMAND.findall(path.read_text(encoding="utf-8")):
            assert command in ALLOWED_SAK_COMMANDS, (
                f"{path.relative_to(ROOT)} names unknown subcommand 'sak {command}'"
            )


def test_prompt_ids_are_within_the_catalog_ranges() -> None:
    for path in skill_texts():
        for prefix, number in PROMPT_ID.findall(path.read_text(encoding="utf-8")):
            maximum = PROMPT_ID_RANGES[prefix]
            assert 1 <= int(number) <= maximum, (
                f"{path.relative_to(ROOT)} names out-of-range prompt {prefix}-{number}"
            )


def test_operating_contract_and_verdicts_are_present() -> None:
    text = "\n".join(path.read_text(encoding="utf-8") for path in skill_texts())
    for term in ("confirmed", "needs_validation", "rejected"):
        assert term in text, f"the skill does not mention the {term!r} verdict"
    assert "dry-run" in text
    assert "scope.md" in text
    assert "evidence" in text


def test_skill_does_not_ship_placeholder_instructions() -> None:
    for path in skill_texts():
        text = path.read_text(encoding="utf-8")
        for marker in ("TODO", "FIXME", "lorem ipsum", "<insert"):
            assert marker not in text, f"{path.relative_to(ROOT)} contains placeholder {marker!r}"
