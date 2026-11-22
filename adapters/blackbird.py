"""Blackbird adapter: external, GPL-3.0 username/email enumeration.

Blackbird is never vendored or installed by sak.  The adapter expects an operator-managed
checkout under ``vendor/external/blackbird`` (gitignored) and refuses cleanly when that
checkout or its Python environment is missing.
"""

from __future__ import annotations

import csv
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ADAPTER_ID = "blackbird"
NAME = "Blackbird"
REQUIRES = ("git", "python3")
DESTINATION_POLICY = "external"
DESTINATION_REFUSAL = (
    "blackbird enumerates third-party sites from its external site list, not the plan target; "
    "scope.md cannot authorize that destination set and the tool exposes no truthful request "
    "bound, so execute is refused. Dry runs, checkout checks and CSV parsing remain available; "
    "run the external tool manually under separate authorization."
)
LICENSE_NOTICE = (
    "Blackbird is GPL-3.0 licensed and its bundled site data carries CC BY-NC-SA terms. "
    "It stays external under vendor/external/blackbird (gitignored); sak never vendors, "
    "redistributes or auto-installs it. Review the upstream license before use."
)
REPO_URL = "https://github.com/p1ngul1n0/blackbird"
EXISTS_VALUES = {"yes", "true", "1", "found", "exists", "y"}
_TARGET_FIELDS = ("url", "uri", "link", "profile")
_SITE_FIELDS = ("site", "name", "service", "platform")
_EXISTS_FIELDS = ("exists", "found", "status", "result")
_METADATA_FIELDS = ("metadata", "meta", "details")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def blackbird_root() -> Path:
    override = os.environ.get("SAK_BLACKBIRD_DIR")
    if override:
        return Path(override).expanduser()
    return repo_root() / "vendor" / "external" / "blackbird"


def _python(root: Path) -> str | None:
    override = os.environ.get("SAK_BLACKBIRD_PYTHON")
    if override:
        return override
    for candidate in (root / ".venv" / "bin" / "python", root / "venv" / "bin" / "python"):
        if candidate.is_file():
            return str(candidate)
    return shutil.which("python3") or (sys.executable or None)


def _options(step: dict[str, Any]) -> dict[str, Any]:
    return dict(step.get("options") or {})


def install_hints() -> list[str]:
    root = blackbird_root()
    return [
        f"git clone {REPO_URL} {root}",
        f"python3 -m venv {root / '.venv'}",
        f"{root / '.venv' / 'bin' / 'pip'} install -r {root / 'requirements.txt'}",
        "these are operator instructions only; sak never runs them",
    ]


def check() -> dict[str, Any]:
    """Report checkout and interpreter presence without installing or cloning."""
    root = blackbird_root()
    entry = root / "blackbird.py"
    python = _python(root)
    missing: list[str] = []
    if not entry.is_file():
        missing.append("blackbird checkout")
    if python is None:
        missing.append("blackbird python environment")
    notes = [
        f"external checkout expected at {root} (gitignored; never vendored)",
        "sak does not run git clone, pip install or any setup command",
    ]
    return {
        "adapter": ADAPTER_ID,
        "available": not missing,
        "binary": str(entry) if entry.is_file() else None,
        "python": python,
        "version": None,
        "missing": missing,
        "hints": install_hints() if missing else [],
        "notes": notes,
        "license_notice": LICENSE_NOTICE,
        "license": "GPL-3.0",
        "data_terms": "CC BY-NC-SA",
    }


def estimate_requests(step: dict[str, Any], seconds: int = 60) -> int:
    """No truthful request bound exists: the external site list decides the count.

    Returning 0 avoids claiming a bound the adapter cannot enforce; executions are refused
    by the destination policy before the budget is consulted.
    """
    del step, seconds
    return 0


def _command(step: dict[str, Any], python: str, entry: str, csv_path: str | Path) -> list[str]:
    options = _options(step)
    username = options.get("username")
    email = options.get("email")
    if not username and not email:
        raise ValueError(
            "blackbird needs step options.username or options.email; it does not scan a URL target"
        )
    command = [python, entry]
    if username:
        command.extend(["--username", str(username)])
    if email:
        command.extend(["--email", str(email)])
    command.extend(["--csv", str(csv_path)])
    return command


def build(
    step: dict[str, Any],
    target: str,
    *,
    run_dir: str | Path | None = None,
    binary: str | None = None,
) -> dict[str, Any]:
    """Build the dry-run command for a username or email input."""
    del target, run_dir  # the web target is unused; no capture is kept under the run directory
    root = blackbird_root()
    entry = binary or str(root / "blackbird.py")
    python = _python(root) or "python3"
    command = _command(step, python, entry, "<temporary csv, deleted after parsing>")
    return {
        "command": command,
        "display": " ".join(command),
        "notes": [
            "Blackbird stays external: GPL-3.0 code with CC BY-NC-SA site data",
            "its site list, not the plan target, decides the destinations; execute is refused",
            "the CSV is parsed from a temporary file and deleted; no raw capture is retained",
        ],
        "requires_scope": True,
        "output_path": None,
        "license_notice": LICENSE_NOTICE,
    }


def _pick(row: dict[str, str], fields: tuple[str, ...]) -> str:
    lowered = {str(key).strip().lower(): value for key, value in row.items() if key is not None}
    for field in fields:
        value = lowered.get(field)
        if value:
            return str(value).strip()
    return ""


def _slug(value: Any) -> str:
    return re.sub(r"[^a-z0-9._-]+", "-", str(value or "unknown").lower()).strip("-") or "unknown"


def parse(text: str) -> list[dict[str, Any]]:
    """Normalize Blackbird CSV rows into candidate finding records for existing accounts."""
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        return []
    findings: list[dict[str, Any]] = []
    for row in reader:
        if not isinstance(row, dict):
            continue
        exists = _pick(row, _EXISTS_FIELDS).lower()
        if exists not in EXISTS_VALUES:
            continue
        url = _pick(row, _TARGET_FIELDS)
        site = _pick(row, _SITE_FIELDS) or url
        if not url and not site:
            continue
        username = _pick(row, ("username", "email", "name", "account"))
        evidence = {
            "site": site or None,
            "url": url or None,
            "username": username or None,
            "metadata": _pick(row, _METADATA_FIELDS) or None,
        }
        findings.append(
            {
                "id": f"blackbird:{_slug(site)}:{_slug(username or 'account')}",
                "title": f"Account exists on {site or url}",
                "severity": "info",
                "status": "needs_validation",
                "source": "blackbird",
                "target": url or site,
                "evidence": {key: value for key, value in evidence.items() if value},
            }
        )
    return findings


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def execute(
    step: dict[str, Any],
    target: str,
    *,
    binary: str | None = None,
    timeout: int = 300,
    run_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Run Blackbird once from the external checkout and parse its CSV output."""
    root = blackbird_root()
    entry = root / "blackbird.py"
    if not entry.is_file():
        return {
            "adapter": ADAPTER_ID,
            "refused": True,
            "reason": f"blackbird checkout not found at {root}",
            "hints": install_hints(),
            "license_notice": LICENSE_NOTICE,
            "findings": [],
        }
    python = _python(root)
    if python is None:
        return {
            "adapter": ADAPTER_ID,
            "refused": True,
            "reason": "no Python interpreter found for the Blackbird checkout",
            "hints": install_hints(),
            "license_notice": LICENSE_NOTICE,
            "findings": [],
        }

    plan = build(step, target, run_dir=run_dir, binary=str(entry))
    started = time.monotonic()
    timed_out = False
    raw = ""
    try:
        with tempfile.TemporaryDirectory(prefix="sak-blackbird-") as temporary:
            csv_path = Path(temporary) / "blackbird.csv"
            command = _command(step, python, str(entry), csv_path)
            try:
                completed = subprocess.run(
                    command, capture_output=True, text=True, timeout=timeout, check=False
                )
                returncode: int | None = completed.returncode
                stdout, stderr = completed.stdout, completed.stderr
            except subprocess.TimeoutExpired as exc:
                timed_out = True
                returncode = None
                stdout, stderr = _text(exc.stdout), _text(exc.stderr)
            if csv_path.is_file():
                raw = csv_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {
            "adapter": ADAPTER_ID,
            "refused": True,
            "reason": f"cannot prepare a temporary CSV for blackbird: {exc}",
            "hints": install_hints(),
            "license_notice": LICENSE_NOTICE,
            "findings": [],
        }
    duration = round(time.monotonic() - started, 3)

    return {
        "adapter": ADAPTER_ID,
        "command": command,
        "returncode": returncode,
        "timed_out": timed_out,
        "duration_seconds": duration,
        "stdout": stdout,
        "stderr": stderr,
        "output_path": None,
        "findings": parse(raw) if raw.strip() else [],
        "notes": plan["notes"],
        "license_notice": LICENSE_NOTICE,
    }
