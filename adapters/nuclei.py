"""Nuclei adapter: template-based HTTP scanning with conservative defaults.

The adapter only inspects the host in :func:`check`; it never downloads templates,
updates nuclei or contacts a target.  A command is built for a dry run and only run
through ``sak run --execute`` after the scope and budget gates pass.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

ADAPTER_ID = "nuclei"
NAME = "Nuclei"
REQUIRES = ("nuclei",)
DESTINATION_POLICY = "target"
LICENSE_NOTICE = (
    "Nuclei is MIT licensed (github.com/projectdiscovery/nuclei). Install it with the "
    "operator's package manager; sak never vendors or redistributes it."
)
INSTALL_HINTS = (
    "brew install nuclei",
    "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
)

DEFAULT_OPTIONS: dict[str, Any] = {
    "severity": "medium,high,critical",
    "rate_limit": 10,
    "timeout": 10,
    "retries": 1,
    "interactsh": False,
    "templates": None,
}
SEVERITIES = ("info", "low", "medium", "high", "critical", "unknown")


def _options(step: dict[str, Any]) -> dict[str, Any]:
    merged = dict(DEFAULT_OPTIONS)
    for key, value in (step.get("options") or {}).items():
        if key in merged:
            merged[key] = value
    return merged


def _severity(value: Any) -> str:
    tokens = [token.strip().lower() for token in str(value or "").split(",") if token.strip()]
    if not tokens:
        raise ValueError("nuclei severity list is empty")
    unknown = [token for token in tokens if token not in SEVERITIES]
    if unknown:
        raise ValueError(
            f"unknown nuclei severity {', '.join(unknown)}; choose from {', '.join(SEVERITIES)}"
        )
    return ",".join(tokens)


def _positive_int(value: Any, name: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"nuclei option {name} must be an integer") from exc
    if number < 1:
        raise ValueError(f"nuclei option {name} must be at least 1")
    return number


def _binary(binary: str | None = None) -> str | None:
    return binary or shutil.which("nuclei")


def _version(binary: str) -> str | None:
    try:
        completed = subprocess.run(
            [binary, "-version"], capture_output=True, text=True, timeout=3, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    lines = (completed.stdout or completed.stderr or "").strip().splitlines()
    return lines[0].strip() if lines else None


def templates_dir() -> Path:
    """Default local template directory Nuclei uses; never created or updated here."""
    return Path.home() / ".local" / "nuclei-templates"


def check() -> dict[str, Any]:
    """Report whether Nuclei is installed without touching the network."""
    binary = _binary()
    templates_found = templates_dir().is_dir()
    notes = [
        "check() only inspects the host; it never runs -update-templates or contacts a target",
        "template updates are a manual operator action (nuclei -update-templates)",
    ]
    if not templates_found:
        notes.append(
            f"no templates found at {templates_dir()}; the operator must install them before an execute run"
        )
    if binary is None:
        return {
            "adapter": ADAPTER_ID,
            "available": False,
            "binary": None,
            "version": None,
            "templates_found": templates_found,
            "missing": ["nuclei"],
            "hints": list(INSTALL_HINTS),
            "notes": notes,
            "license_notice": LICENSE_NOTICE,
        }
    return {
        "adapter": ADAPTER_ID,
        "available": True,
        "binary": binary,
        "version": _version(binary),
        "templates_found": templates_found,
        "missing": [],
        "hints": [],
        "notes": notes,
        "license_notice": LICENSE_NOTICE,
    }


def estimate_requests(step: dict[str, Any], seconds: int = 60) -> int:
    """Worst-case request estimate for a run limited to *seconds*."""
    options = _options(step)
    return _positive_int(options["rate_limit"], "rate_limit") * max(1, int(seconds))


def _templates(step: dict[str, Any]) -> str | None:
    """Validate an optional template path; remote URLs are never fetched."""
    options = _options(step)
    value = options.get("templates")
    if not value:
        return None
    text = str(value).strip()
    if "://" in text or text.startswith(("//", "http:", "https:")):
        raise ValueError("nuclei templates must be an existing local path; remote template URLs are not allowed")
    path = Path(text).expanduser()
    if not path.is_file() and not path.is_dir():
        raise ValueError(f"nuclei templates path does not exist: {path}")
    return str(path)


def build(
    step: dict[str, Any],
    target: str,
    *,
    run_dir: str | Path | None = None,
    binary: str | None = None,
) -> dict[str, Any]:
    """Build the dry-run command; nothing is executed and no capture is written."""
    del run_dir  # raw tool output is parsed from stdout and never retained under the run directory
    resolved = _binary(binary)
    options = _options(step)
    executable = resolved or "nuclei"
    command = [
        executable,
        "-u",
        target,
        "-jsonl",
        "-disable-update-check",
        "-no-color",
        "-silent",
        "-severity",
        _severity(options["severity"]),
        "-rate-limit",
        str(_positive_int(options["rate_limit"], "rate_limit")),
        "-timeout",
        str(_positive_int(options["timeout"], "timeout")),
        "-retries",
        str(_positive_int(options["retries"], "retries")),
    ]
    if not options.get("interactsh"):
        command.append("-no-interactsh")
    templates = _templates(step)
    if templates:
        command.extend(["-t", templates])

    notes = [
        "-no-interactsh is on unless the step sets options.interactsh: true",
        "template and update checks are disabled; templates must already exist as local paths",
        "rate, timeout and retries come from the step options, not from tool defaults",
        "output is parsed from stdout; no raw capture is kept under the run directory",
    ]
    return {
        "command": command,
        "display": " ".join(command),
        "notes": notes,
        "requires_scope": True,
        "output_path": None,
        "license_notice": LICENSE_NOTICE,
    }


def _slug(value: Any) -> str:
    return re.sub(r"[^a-z0-9._-]+", "-", str(value or "unknown").lower()).strip("-") or "unknown"


def parse(text: str) -> list[dict[str, Any]]:
    """Normalize Nuclei JSONL into candidate finding records."""
    findings: list[dict[str, Any]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid nuclei JSONL at line {number}: {exc}") from exc
        if not isinstance(payload, dict):
            raise ValueError(f"invalid nuclei JSONL at line {number}: expected an object")
        info = payload.get("info") if isinstance(payload.get("info"), dict) else {}
        template = str(payload.get("template-id") or info.get("template-id") or "unknown")
        host = payload.get("host") or ""
        matched_at = payload.get("matched-at") or payload.get("url") or host
        evidence = {
            "template": template,
            "type": payload.get("type"),
            "matcher": payload.get("matcher-name"),
            "extracted": payload.get("extracted-results") or [],
            "tags": info.get("tags") or [],
            "host": host or None,
        }
        findings.append(
            {
                "id": f"nuclei:{_slug(template)}:{_slug(host or matched_at)}",
                "title": str(info.get("name") or template),
                "severity": str(info.get("severity") or "unknown").lower(),
                "status": "needs_validation",
                "source": "nuclei",
                "target": str(matched_at or ""),
                "evidence": {key: value for key, value in evidence.items() if value not in (None, [], "")},
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
    """Run Nuclei once and parse its output. Callers gate scope and budget first."""
    resolved = _binary(binary)
    if resolved is None:
        return {
            "adapter": ADAPTER_ID,
            "refused": True,
            "reason": "nuclei is not installed",
            "hints": list(INSTALL_HINTS),
            "findings": [],
        }
    plan = build(step, target, run_dir=run_dir, binary=resolved)

    started = time.monotonic()
    timed_out = False
    try:
        completed = subprocess.run(
            plan["command"], capture_output=True, text=True, timeout=timeout, check=False
        )
        returncode: int | None = completed.returncode
        stdout, stderr = completed.stdout, completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = None
        stdout, stderr = _text(exc.stdout), _text(exc.stderr)
    duration = round(time.monotonic() - started, 3)

    raw = stdout
    result: dict[str, Any] = {
        "adapter": ADAPTER_ID,
        "command": plan["command"],
        "returncode": returncode,
        "timed_out": timed_out,
        "duration_seconds": duration,
        "stdout": stdout,
        "stderr": stderr,
        "output_path": None,
        "findings": [],
        "notes": plan["notes"],
    }
    try:
        result["findings"] = parse(raw) if raw.strip() else []
    except ValueError as exc:
        result["parse_error"] = str(exc)
    return result
