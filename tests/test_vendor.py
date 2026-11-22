"""Vendored MIT skills: pins, licenses, checksums and catalog cards.

These tests are offline.  They read the recorded manifest in
``vendor/sources.lock.json`` and compare it with the files on disk, so drift in
either direction fails.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sak import catalog as catalog_module

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "vendor"
SKILLS = VENDOR / "skills"
LOCK_PATH = VENDOR / "sources.lock.json"
CATALOG = ROOT / "catalog"

EXPECTED = {
    "pwn-hunter": {
        "url": "https://github.com/BountyForge-xyz/pwn-skill",
        "commit": "403310598eab3c99c24082795c35b76e790ed6a5",
        "license": "MIT",
        "local_path": "vendor/skills/pwn-hunter",
        "license_file": "vendor/skills/pwn-hunter/LICENSE",
        "holder": "BountyForge-xyz",
    },
    "security-audit": {
        "url": "https://github.com/cloudflare/security-audit-skill",
        "commit": "c1c8a8c1471069fb0e188eeaff69b8e8db6564a8",
        "license": "MIT",
        "local_path": "vendor/skills/security-audit",
        "license_file": "vendor/skills/security-audit/LICENSE",
        "holder": "Cloudflare, Inc.",
    },
}


def _lock() -> dict:
    return json.loads(LOCK_PATH.read_text(encoding="utf-8"))


def _sources() -> dict[str, dict]:
    return {source["id"]: source for source in _lock()["sources"]}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_lock_records_both_pinned_commits() -> None:
    lock = _lock()
    assert lock["upstream_content_modified"] is False
    assert lock["lock_version"] == 1
    sources = _sources()
    assert set(sources) == set(EXPECTED)
    for skill_id, expected in EXPECTED.items():
        source = sources[skill_id]
        assert source["commit"] == expected["commit"], skill_id
        assert source["url"] == expected["url"], skill_id
        assert source["default_branch"] == "main", skill_id
        assert source["license"] == expected["license"], skill_id
        assert source["local_path"] == expected["local_path"], skill_id
        assert source["license_file"] == expected["license_file"], skill_id
        # A pinned commit is a full 40-character SHA, and the fetch date is recorded.
        assert len(source["commit"]) == 40, skill_id
        int(source["commit"], 16)
        assert source["fetched_at"].endswith("Z"), skill_id
        assert source["copy_method"], skill_id


def test_provenance_and_notices_cite_pins_and_licenses() -> None:
    provenance = (VENDOR / "PROVENANCE.md").read_text(encoding="utf-8")
    notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    for skill_id, expected in EXPECTED.items():
        for text, where in ((provenance, "PROVENANCE.md"), (notices, "THIRD_PARTY_NOTICES.md")):
            assert expected["commit"] in text, f"{where} misses {skill_id} commit"
            assert expected["url"] in text, f"{where} misses {skill_id} url"
            assert expected["local_path"] in text, f"{where} misses {skill_id} path"
            assert "MIT" in text, f"{where} misses the license name"
    assert "unmodified" in provenance.lower()


def test_provenance_documents_the_integration_contract() -> None:
    provenance = (VENDOR / "PROVENANCE.md").read_text(encoding="utf-8")
    assert "install.sh" in provenance
    assert ".opencode/skills/" in provenance
    assert "~/.agents/skills/" in provenance
    assert "invoke.type: skill" in (CATALOG / "tools" / "pwn-hunter.yaml").read_text(encoding="utf-8")
    assert "invoke.type: skill" in (CATALOG / "tools" / "security-audit.yaml").read_text(encoding="utf-8")


@pytest.mark.parametrize("skill_id", sorted(EXPECTED))
def test_license_and_skill_entrypoint_exist(skill_id: str) -> None:
    expected = EXPECTED[skill_id]
    skill_dir = ROOT / expected["local_path"]
    skill_md = skill_dir / "SKILL.md"
    license_file = ROOT / expected["license_file"]
    assert skill_md.is_file(), f"missing {skill_md}"
    assert skill_md.stat().st_size > 0
    assert license_file.is_file(), f"missing {license_file}"
    license_text = license_file.read_text(encoding="utf-8")
    assert license_text.startswith("MIT License"), skill_id
    assert expected["holder"] in license_text, skill_id
    # The skill entry point is an agent skill with YAML frontmatter.
    assert skill_md.read_text(encoding="utf-8").startswith("---\n"), skill_id


def test_no_nested_git_directory_survives_the_copy() -> None:
    leftovers = [path for path in SKILLS.rglob(".git") if path.exists()]
    assert leftovers == [], leftovers
    assert not (SKILLS / "pwn-hunter" / ".git").exists()
    assert not (SKILLS / "security-audit" / ".git").exists()


def test_copied_files_match_manifest() -> None:
    sources = _sources()
    for skill_id, source in sources.items():
        skill_dir = ROOT / source["local_path"]
        manifest = source["copied_files"]
        assert manifest, skill_id
        on_disk = {
            str(path.relative_to(skill_dir))
            for path in skill_dir.rglob("*")
            if path.is_file()
        }
        assert on_disk == set(manifest), f"{skill_id}: file set drifted from the manifest"
        for relative, digest in sorted(manifest.items()):
            actual = _sha256(skill_dir / relative)
            assert actual == digest, f"{skill_id}/{relative} changed after vendoring"


def test_security_audit_reference_documents_and_validators_are_present() -> None:
    skill_dir = SKILLS / "security-audit"
    required = [
        "report-schema.json",
        "validate-findings.cjs",
        "validate-coverage-ledger.cjs",
        "validate-findings.test.cjs",
        "validate-coverage-ledger.test.cjs",
        "ATTACK-CLASSES.md",
        "HUNTING.md",
        "RECONNAISSANCE.md",
        "VALIDATION-AND-REPORTING.md",
    ]
    for name in required:
        assert (skill_dir / name).is_file(), name


def test_catalog_cards_validate() -> None:
    loaded = catalog_module.load_catalog(CATALOG)
    issues = catalog_module.validate_catalog(loaded)
    assert issues == [], issues
    tools = {card.id: card for card in loaded.of_type("tool")}
    for skill_id, expected in EXPECTED.items():
        assert skill_id in tools, skill_id
        card = tools[skill_id]
        data = card.data
        assert data["kind"] == "skill"
        assert data["status"] == "verified"
        assert data["license"] == "MIT"
        assert data["adapter"] is None
        assert any(source["url"] == expected["url"] for source in data["sources"])
        notes = data["notes"]
        assert expected["commit"] in notes
        assert f"local_path: {expected['local_path']}" in notes
        assert "strengths:" in notes and "weaknesses:" in notes
        assert "integration:" in notes
