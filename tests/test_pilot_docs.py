"""Docs contract for the consolidated pilot runbook and acceptance matrix.

These tests are offline: they read the three pilot documents and assert that the
runbook keeps both targets, both environments, the tested command names, the
four-cell matrix and the secret/placeholder hygiene the pack rules require.
Nothing here starts Docker, a browser or an SSH tunnel.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PILOT = ROOT / "docs" / "pilot.md"
INDEX = ROOT / "targets" / "pilot" / "README.md"
ACCEPTANCE = ROOT / "targets" / "pilot" / "acceptance.md"
DVWA_COMPOSE = ROOT / "targets" / "dvwa" / "compose.yaml"
VULN_BANK_CLONE = ROOT / "targets" / "vuln-bank" / "clone.sh"
TUNNEL = ROOT / "scripts" / "legion-tunnel.sh"

DOCS = (PILOT, INDEX, ACCEPTANCE)

PINNED_COMMIT = "41c5b056f9ae8a8b15c77ea79f1419356b321634"

REQUIRED_PILOT_HEADINGS = (
    "## 1. Status and honesty statement",
    "## 2. Prerequisites",
    "## 3. Path A — Kali WSL with local Docker",
    "## 4. Path B — Mac with `scripts/legion-tunnel.sh`",
    "## 5. Playwright in the pilot flow",
    "## 6. Candidates, imported records and confirmed findings",
    "## 7. Failure handling",
    "## 8. Acceptance, evidence and cleanup",
    "## 9. What remains unproven",
)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_pilot_documents_exist() -> None:
    for path in DOCS:
        assert path.is_file(), f"missing pilot document: {path}"


def test_required_commands_still_exist_in_the_repo() -> None:
    assert DVWA_COMPOSE.is_file()
    assert VULN_BANK_CLONE.is_file()
    assert TUNNEL.is_file()
    compose = read(DVWA_COMPOSE)
    assert "vulnerables/web-dvwa" in compose
    assert "127.0.0.1:${DVWA_PORT:-8080}:80" in compose
    assert PINNED_COMMIT in read(VULN_BANK_CLONE)
    assert "--execute" in read(TUNNEL)


def test_pilot_runbook_has_the_required_sections() -> None:
    text = read(PILOT)
    for heading in REQUIRED_PILOT_HEADINGS:
        assert heading in text, f"docs/pilot.md is missing heading: {heading}"


def test_runbook_names_both_targets_and_both_environments() -> None:
    text = read(PILOT)
    for name in ("DVWA", "vuln-bank"):
        assert name in text
    for environment in ("Kali WSL", "Mac", "scripts/legion-tunnel.sh"):
        assert environment in text
    assert "http://127.0.0.1:8080" in text
    assert "http://127.0.0.1:5000" in text
    assert "legion-ts" in text
    assert "ssh -N -L 8080:127.0.0.1:8080 legion-ts" in text


def test_runbook_records_the_exact_command_sequence() -> None:
    text = read(PILOT)
    for command in (
        "sh targets/dvwa/run.sh --dry-run",
        "sh targets/dvwa/run.sh --run-dir runs/pilot-dvwa-kali",
        "sh targets/dvwa/run.sh --no-compose --url http://127.0.0.1:8080 --run-dir runs/pilot-dvwa-mac",
        "sh targets/vuln-bank/clone.sh --dry-run",
        "sh targets/vuln-bank/clone.sh",
        "sh targets/vuln-bank/run.sh --dry-run",
        "sh targets/vuln-bank/run.sh --execute --run-dir runs/pilot-vuln-bank-kali",
        "sh scripts/legion-tunnel.sh --execute 8080",
        "sh scripts/legion-tunnel.sh --execute 5000",
        "uv run sak plan --suite web-blackbox --target http://127.0.0.1:5000 --run-dir \"$RUN\"",
        "uv run sak run --run runs/pilot-dvwa-kali --step playwright --execute",
        "uv run sak findings import",
        "uv run sak findings validate",
        "uv run sak findings dedupe --write",
        "uv run sak findings status",
        "uv run sak report",
    ):
        assert command in text, f"docs/pilot.md is missing command: {command}"
    assert "BASE_URL=http://127.0.0.1:5000 npx playwright test" in text


def test_findings_stages_are_explained() -> None:
    text = read(PILOT)
    for phrase in (
        "candidate",
        "needs_validation",
        "confirmed",
        "sak findings import",
        "never claims `confirmed`",
    ):
        assert phrase in text
    assert "findings/playwright.json" in text
    assert "evidence/" in text


def test_failure_handling_covers_the_required_symptoms() -> None:
    text = read(PILOT)
    symptoms = (
        "missing browser",
        "docker: command not found",
        "ssh legion-ts` works",
        "port is already allocated",
        "login was rejected",
        "empty",
        "budget",
    )
    for symptom in symptoms:
        assert symptom in text, f"failure table is missing symptom: {symptom}"
    for next_command in (
        "npx playwright install chromium",
        "sh targets/dvwa/run.sh --no-compose --url http://127.0.0.1:8080",
        "wsl.exe -d kali-linux",
        "DVWA_PORT=8081 sh targets/dvwa/run.sh --url http://127.0.0.1:8081",
        "sh targets/vuln-bank/run.sh --execute --target http://127.0.0.1:5001 --port 5001",
        "sh targets/dvwa/setup.sh --url http://127.0.0.1:8080",
        "uv run sak doctor",
        "uv run sak report runs/pilot-dvwa-kali",
    ):
        assert next_command in text, f"failure table is missing next command: {next_command}"


def test_index_records_every_target_field() -> None:
    text = read(INDEX)
    for field in (
        "Upstream",
        "Pin",
        "Required ports",
        "Credentials location",
        "Compose / clone",
        "Scope file",
        "Kali run command",
        "Mac run command",
        "Cleanup",
        "Expected evidence",
    ):
        assert field in text, f"target index is missing field: {field}"
    assert "https://github.com/digininja/DVWA" in text
    assert "https://github.com/Commando-X/vuln-bank" in text
    assert PINNED_COMMIT in text
    assert "targets/dvwa/.env" in text
    assert "docs/targets/vuln-bank.md#test-accounts" in text
    assert "vendor/external/vuln-bank" in text
    assert "127.0.0.1:8080" in text
    assert "127.0.0.1:5000" in text


def test_acceptance_matrix_marks_every_cell_lead_run() -> None:
    text = read(ACCEPTANCE)
    cells = {
        "DVWA / Kali": "runs/pilot-dvwa-kali/",
        "DVWA / Mac tunnel": "runs/pilot-dvwa-mac/",
        "vuln-bank / Kali": "runs/pilot-vuln-bank-kali/",
        "vuln-bank / Mac tunnel": "runs/pilot-vuln-bank-mac/",
    }
    for cell, run_dir in cells.items():
        assert cell in text, f"acceptance matrix is missing cell: {cell}"
        assert run_dir in text, f"acceptance matrix is missing evidence root: {run_dir}"
    assert text.count("`lead-run`") >= 4
    assert "`lead`" in text
    assert "REPORT.md" in text
    assert "findings.json" in text
    assert "evidence/" in text
    assert "## Result log" in text


def test_documents_do_not_claim_live_worker_results() -> None:
    pilot = read(PILOT)
    acceptance = read(ACCEPTANCE)
    assert "**not**" in pilot and "worker test results" in pilot
    assert "No cell is claimed by a worker" in acceptance
    assert "Status" in acceptance and "lead-run" in acceptance


def test_no_unresolved_placeholders() -> None:
    placeholder = re.compile(
        r"(?i)\b(TODO|TBD|FIXME|XXX|CHANGEME|PLACEHOLDER)\b|your-|<[A-Za-z][^>\n]*>"
    )
    for path in DOCS:
        for number, line in enumerate(read(path).splitlines(), start=1):
            match = placeholder.search(line)
            assert match is None, f"{path}:{number} has an unresolved placeholder: {match.group(0)!r}"


def test_no_committed_credentials() -> None:
    known_lab_secrets = (
        "admin123",
        "bookstore123",
        "pwnshop123",
        "zerohealth123",
        "DVWA_PASSWORD=password",
        "POSTGRES_PASSWORD=",
    )
    assignment = re.compile(
        r"(?im)^\s*(DVWA_PASSWORD|APP_PASSWORD|VULNBANK_[A-Z_]*PASSWORD|POSTGRES_PASSWORD)\s*=\s*(\S+)"
    )
    for path in DOCS:
        text = read(path)
        for secret in known_lab_secrets:
            assert secret not in text, f"{path} contains a lab default credential: {secret}"
        for match in assignment.finditer(text):
            value = match.group(2)
            assert value in {"${DVWA_PASSWORD}", "$DVWA_PASSWORD"}, (
                f"{path} assigns a literal password to {match.group(1)}"
            )
