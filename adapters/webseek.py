"""Webseek adapter: external research CLI driven through npx.

Webseek is a research helper, not an attack tool.  It needs Node/npx, a provider and an
API key for a live query, so a dry run is deliberately allowed without a key while an
execute run refuses cleanly until ``WEBSEEK_API_KEY`` is present.  The adapter never
installs the package and never vendors the CLI.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

ADAPTER_ID = "webseek"
NAME = "Webseek"
REQUIRES = ("npx",)
DESTINATION_POLICY = "provider"
DESTINATION_REFUSAL = (
    "webseek sends the query to a search provider chosen by the CLI and its configuration, not "
    "to the plan target; scope.md cannot authorize that destination and every query is billed, "
    "so execute is refused. Dry runs, JSON parsing and usage/cost extraction remain available "
    "for research prepared outside sak."
)
LICENSE_NOTICE = (
    "Webseek and its provider APIs have their own licenses and terms of service. Use is "
    "billed by the provider; sak never vendors, pins or installs the CLI and never reads a "
    "key except to pass the operator's environment through to the subprocess."
)
API_KEY_ENV = "WEBSEEK_API_KEY"
PROVIDER_ENV = "WEBSEEK_PROVIDER"
DEFAULT_OPTIONS: dict[str, Any] = {"max_results": 10}

MCP_EXAMPLE: dict[str, Any] = {
    "mcpServers": {
        "webseek": {
            "command": "npx",
            "args": ["-y", "webseek-mcp"],
            "env": {API_KEY_ENV: f"${{{API_KEY_ENV}}}", PROVIDER_ENV: "example-provider"},
        }
    }
}
MCP_NOTE = (
    "Example only, for a research workstation: add this to the MCP client configuration and "
    "supply the key through the environment. Do not commit a filled-in copy."
)


def _options(step: dict[str, Any]) -> dict[str, Any]:
    merged = dict(DEFAULT_OPTIONS)
    for key, value in (step.get("options") or {}).items():
        merged[key] = value
    return merged


def _api_key(options: dict[str, Any] | None = None) -> str | None:
    options = options or {}
    return str(options.get("api_key") or os.environ.get(API_KEY_ENV) or "") or None


def _provider(options: dict[str, Any] | None = None) -> str | None:
    options = options or {}
    return str(options.get("provider") or os.environ.get(PROVIDER_ENV) or "") or None


def _binary(binary: str | None = None) -> str | None:
    return binary or shutil.which("npx") or shutil.which("webseek")


def check() -> dict[str, Any]:
    """Report Node/npx and key presence; never queries a provider."""
    binary = _binary()
    options: dict[str, Any] = {}
    key_present = _api_key(options) is not None
    provider = _provider(options)
    notes = [
        "check() never queries a provider and never spends credit",
        f"a live query needs {API_KEY_ENV}; a dry run does not",
        "execute is refused: the provider destination is chosen by the CLI, not by scope.md",
        MCP_NOTE,
    ]
    missing = [] if binary else ["npx"]
    if not key_present:
        notes.append(f"{API_KEY_ENV} is not set; execute runs will refuse until it is exported")
    if provider is None:
        notes.append(f"set options.provider or {PROVIDER_ENV} to select a provider")
    return {
        "adapter": ADAPTER_ID,
        "available": binary is not None,
        "binary": binary,
        "version": None,
        "api_key_present": key_present,
        "provider": provider,
        "missing": missing,
        "hints": ["install Node.js (npx ships with it): brew install node"] if missing else [],
        "notes": notes,
        "license_notice": LICENSE_NOTICE,
        "mcp_example": MCP_EXAMPLE,
    }


def estimate_requests(step: dict[str, Any], seconds: int = 60) -> int:
    """One search request plus one fetch per requested result."""
    if seconds <= 0:
        return 0
    try:
        results = int(_options(step).get("max_results", 10))
    except (TypeError, ValueError):
        results = 10
    return max(1, results) + 1


def _query(step: dict[str, Any], target: str) -> str:
    options = _options(step)
    query = options.get("query") or step.get("query")
    if query:
        return str(query)
    if target and not target.startswith("<"):
        return target
    raise ValueError("webseek needs options.query (or a plan target) for the research prompt")


def build(
    step: dict[str, Any],
    target: str,
    *,
    run_dir: str | Path | None = None,
    binary: str | None = None,
) -> dict[str, Any]:
    """Build the dry-run command without reading or requiring an API key."""
    del run_dir  # results are read from stdout; no tool-side output file is assumed
    options = _options(step)
    executable = _binary(binary) or "npx"
    command = [
        executable,
        "--yes",
        "webseek",
        _query(step, target),
        "--json",
        "--max-results",
        str(_positive_int(options.get("max_results", 10), "max_results")),
    ]
    provider = _provider(options)
    if provider:
        command.extend(["--provider", provider])
    for extra in options.get("args") or []:
        command.append(str(extra))
    return {
        "command": command,
        "display": " ".join(command),
        "notes": [
            f"provider billed per query; {API_KEY_ENV} is read from the environment at execute time",
            "execute is refused: the provider destination is chosen by the CLI, not by scope.md",
            "the CLI flag surface follows the installed webseek version; use options.args for extras",
            MCP_NOTE,
        ],
        "requires_scope": False,
        "output_path": None,
        "license_notice": LICENSE_NOTICE,
        "mcp_example": MCP_EXAMPLE,
    }


def _positive_int(value: Any, name: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"webseek option {name} must be an integer") from exc
    if number < 1:
        raise ValueError(f"webseek option {name} must be at least 1")
    return number


def _slug(value: Any) -> str:
    return re.sub(r"[^a-z0-9._-]+", "-", str(value or "unknown").lower()).strip("-") or "unknown"


def _payload(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid webseek JSON: {exc}") from exc


def parse(text: str) -> list[dict[str, Any]]:
    """Normalize Webseek JSON results into research candidate records."""
    payload = _payload(text)
    if isinstance(payload, dict):
        items = payload.get("results") or payload.get("items") or payload.get("data") or []
    elif isinstance(payload, list):
        items = payload
    else:
        items = []
    findings: list[dict[str, Any]] = []
    for index, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or item.get("link") or "")
        title = str(item.get("title") or item.get("name") or url or f"result {index}")
        evidence = {
            "snippet": item.get("snippet") or item.get("description"),
            "rank": item.get("rank") or index,
            "provider": item.get("provider"),
            "published": item.get("published") or item.get("date"),
        }
        findings.append(
            {
                "id": f"webseek:{index}:{_slug(title)}",
                "title": title,
                "severity": "info",
                "status": "needs_validation",
                "source": "webseek",
                "target": url,
                "evidence": {key: value for key, value in evidence.items() if value not in (None, "")},
            }
        )
    return findings


def parse_usage(text: str) -> dict[str, Any]:
    """Extract usage/cost fields when the CLI reports them; empty otherwise."""
    payload = _payload(text)
    if not isinstance(payload, dict):
        return {}
    usage: dict[str, Any] = {}
    raw_usage = payload.get("usage")
    if isinstance(raw_usage, dict):
        for key in ("requests", "queries", "tokens", "credits"):
            if key in raw_usage:
                usage[key] = raw_usage[key]
    for key in ("cost", "cost_usd", "total_cost", "total_cost_usd"):
        if key in payload:
            usage["cost_usd" if "usd" in key or key == "cost" else key] = payload[key]
    for key in ("usage", "cost"):
        if key in payload and not isinstance(payload[key], dict):
            usage.setdefault(key, payload[key])
    if "provider" in payload and "provider" not in usage:
        usage["provider"] = payload["provider"]
    return usage


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
    """Run one Webseek query. The caller has already checked scope and budget."""
    resolved = _binary(binary)
    if resolved is None:
        return {
            "adapter": ADAPTER_ID,
            "refused": True,
            "reason": "npx is not installed",
            "hints": ["brew install node"],
            "findings": [],
        }
    options = _options(step)
    if _api_key(options) is None:
        return {
            "adapter": ADAPTER_ID,
            "refused": True,
            "reason": f"{API_KEY_ENV} is not set; webseek needs a provider key for a live query",
            "hints": [f"export {API_KEY_ENV}=...  # never commit the value", MCP_NOTE],
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
        "usage": {},
        "notes": plan["notes"],
        "license_notice": LICENSE_NOTICE,
    }
    if stdout.strip():
        try:
            result["findings"] = parse(stdout)
            result["usage"] = parse_usage(stdout)
        except ValueError as exc:
            result["parse_error"] = str(exc)
    return result
