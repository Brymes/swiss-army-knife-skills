"""Bounded prompt-hunter runner for ``sak hunt``.

The runner turns a handful of catalog prompt cards into one bounded child hunt
each.  It never contacts a target itself: a child agent runs the card, and this
module enforces the concurrency cap, the per-hunter timeout, the total time
budget and the prompt budget.  Child output is parsed into candidate findings in
the same shape accepted by ``sak findings import``; a failed or timed-out hunter
is an error record, never a confirmed finding.

Runner stdout, stderr and commands are masked before they reach disk.  Raw child
data only lives in memory.  The black-box contract is part of the rendered
prompt: a hunter must not read target source code.

The default runner uses OpenCode's JSON event mode.  The child's final agent
message carries the candidate JSON; it is extracted from the JSONL ``text``
events rather than from the human TUI stream on stderr.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.parse import urlsplit

from . import prompts as prompts_module
from . import run as run_module
from . import util

DEFAULT_MODEL = "nearai/deepseek-ai/DeepSeek-V4.1-Flash-1017-abliterated"
DEFAULT_MAX_AGENTS = 2
MAX_AGENTS = 8
DEFAULT_TIMEOUT_SECONDS = 300.0
MAX_PROMPTS = 12
MAX_PROMPT_CHARS = 12000
MAX_CAPTURE_CHARS = 8000
HUNT_DIRNAME = "hunt"
RUNS_ROOT = "runs"
STATUS_SUCCESS = "success"
STATUS_ERROR = "error"
SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_ALIASES = {
    "moderate": "medium",
    "med": "medium",
    "informational": "info",
    "information": "info",
    "unknown": "info",
    "none": "info",
}
ACCOUNT_ENV = ("SAK_HUNT_ACCOUNT", "SAK_TARGET_ACCOUNT")
OPENCODE_ENV = "SAK_OPENCODE_BIN"
OPENCODE_EVENTS = ("step_start", "text", "step_finish", "tool", "message", "error")
DEFAULT_ACCOUNT = "unauthenticated black-box identity (no credentials supplied)"

_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@]+@")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_PROVIDER_TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"xox[abprs]-[A-Za-z0-9-]{10,}|(?:AKIA|ASIA)[0-9A-Z]{16})\b"
)
_LONG_HEX = re.compile(r"\b[A-Fa-f0-9]{32,}\b")
_COOKIE_ASSIGNMENT = re.compile(
    r"(?i)\b(?:set-)?cookie\s*:\s*[^\r\n]+|"
    r"\b(?:session|sess|sid|csrf)[_-]?[A-Za-z0-9]*\s*[:=]\s*[^\s,;\"'}]+"
)


class HuntError(util.SakError):
    """Raised when a hunt cannot be prepared or launched."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_prompt_ids(value: str | None) -> list[str]:
    """Split a comma/space separated prompt list, preserving order and deduping."""
    ids: list[str] = []
    for token in re.split(r"[,\s]+", str(value or "").strip()):
        if token and token not in ids:
            ids.append(token)
    if not ids:
        raise HuntError("no prompt ids supplied; pass --prompts ID[,ID]")
    return ids


def resolve_run_dir(value: str | Path) -> Path:
    """Resolve a run directory; a bare run name lives under ``runs/``."""
    path = Path(value).expanduser()
    if path.is_absolute() or len(path.parts) > 1:
        return path
    return Path(RUNS_ROOT) / path


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return " ".join(str(value).split()).strip()


def _slug(value: Any, fallback: str) -> str:
    slug = re.sub(r"[^a-z0-9._-]+", "-", _as_text(value).lower()).strip("-._")
    return slug or fallback


def _severity(value: Any) -> str:
    text = _as_text(value).lower()
    if text in SEVERITIES:
        return text
    return SEVERITY_ALIASES.get(text, "info")


def _account_label() -> str:
    for name in ACCOUNT_ENV:
        value = os.environ.get(name)
        if value and value.strip():
            return value.strip()
    return DEFAULT_ACCOUNT


def _token_masks(text: str) -> str:
    masked = _URL_USERINFO.sub(r"\1***@", text)
    masked = _JWT.sub("***", masked)
    masked = _PROVIDER_TOKEN.sub("***", masked)
    masked = _LONG_HEX.sub("***", masked)
    return _COOKIE_ASSIGNMENT.sub(
        lambda match: match.group(0).split(":", 1)[0] + ": ***"
        if ":" in match.group(0)
        else match.group(0).split("=", 1)[0] + "=***",
        masked,
    )


def sanitize_text(value: Any, secrets: Iterable[str] = ()) -> str:
    """Mask known secrets, URL credentials, cookies and token-shaped values."""
    if value is None:
        return ""
    return _token_masks(util.mask_secrets(str(value), secrets))


def sanitize_value(value: Any, secrets: Iterable[str] = ()) -> Any:
    """Recursively sanitize a JSON-like value before it is written or printed."""
    if isinstance(value, str):
        return sanitize_text(value, secrets)
    if isinstance(value, dict):
        return {str(key): sanitize_value(item, secrets) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize_value(item, secrets) for item in value]
    return value


def _secret_values() -> list[str]:
    return util.secret_env_values(dict(os.environ))


_STANDALONE_SUPPORT: dict[str, bool] = {}


def _supports_standalone(executable: str) -> bool:
    """Return True when the installed OpenCode accepts ``run --standalone``."""
    if executable in _STANDALONE_SUPPORT:
        return _STANDALONE_SUPPORT[executable]
    try:
        completed = subprocess.run(
            [executable, "run", "--help"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        supported = "--standalone" in f"{completed.stdout}\n{completed.stderr}"
    except (OSError, subprocess.SubprocessError):
        supported = False
    _STANDALONE_SUPPORT[executable] = supported
    return supported


def _opencode_executable() -> str:
    """Resolve the OpenCode binary, preferring the worker launcher's version.

    ``~/.opencode/bin/opencode`` is the v2 binary used by the pack's launcher;
    a PATH lookup remains the portable fallback.  ``SAK_OPENCODE_BIN`` overrides
    both for an unusual host.
    """
    override = os.environ.get(OPENCODE_ENV)
    if override and override.strip():
        return override.strip()
    preferred = Path.home() / ".opencode" / "bin" / "opencode"
    if preferred.is_file() and os.access(preferred, os.X_OK):
        return str(preferred)
    return shutil.which("opencode") or "opencode"


def runner_command(runner: str | None, model: str) -> list[str]:
    """Build the child command; the prompt is always appended as its last argument.

    The default is OpenCode JSON event mode so the final agent message is
    machine-readable.  ``--standalone`` is included only when the resolved
    binary advertises it, which keeps older OpenCode installs working.
    """
    if runner:
        try:
            tokens = shlex.split(runner)
        except ValueError as exc:
            raise HuntError(f"invalid --runner command: {exc}") from exc
        if not tokens:
            raise HuntError("--runner must name an executable")
        return tokens
    executable = _opencode_executable()
    command = [executable, "run"]
    if _supports_standalone(executable):
        command.append("--standalone")
    command.extend(["--format", "json", "--model", model])
    return command


def load_hunt_cards(catalog: str | Path, ids: Sequence[str]) -> list[Any]:
    """Load exactly the requested prompt cards, failing on unknown ids."""
    try:
        cards = prompts_module.load_prompts(catalog)
    except util.CatalogError as exc:
        if "no YAML cards" in str(exc):
            raise HuntError(f"no prompt cards under {catalog}") from exc
        raise
    if not cards:
        raise HuntError(f"no prompt cards under {catalog}")
    by_id = {card.id: card for card in cards}
    missing = [prompt_id for prompt_id in ids if prompt_id not in by_id]
    if missing:
        raise HuntError(
            f"no prompt card for {', '.join(missing)} under {catalog}; "
            f"known ids include {', '.join(sorted(by_id)[:5])}"
        )
    return [by_id[prompt_id] for prompt_id in ids]


def scope_context(run_dir: Path, target: str) -> dict[str, Any]:
    """Describe authorization from the run's optional ``scope.md``."""
    scope = run_module.load_scope(run_dir)
    context: dict[str, Any] = {
        "present": scope.present,
        "file": str(scope.path) if scope.path is not None else None,
        "hosts": list(scope.hosts),
        "excluded": list(scope.excluded),
        "allowed": None,
        "reason": f"no {run_module.SCOPE_FILENAME} in {run_dir}",
    }
    if scope.present:
        allowed, reason = run_module.scope_allows(scope, target)
        context["allowed"] = allowed
        context["reason"] = reason
    return context


def render_hunter_prompt(
    card: Any,
    *,
    target: str,
    scope: dict[str, Any],
    account: str,
    model: str,
    timeout_seconds: float,
    max_requests: int = 40,
) -> str:
    """Render one bounded hunter prompt with target, scope and account context."""
    card_text = prompts_module.render_prompt(card)
    if len(card_text) > MAX_PROMPT_CHARS:
        card_text = card_text[:MAX_PROMPT_CHARS].rstrip() + "\n\n[card truncated at the prompt budget]"
    allowed = scope.get("allowed")
    if allowed is True:
        scope_line = f"allowed by {scope.get('file')}: {scope.get('reason')}"
    elif allowed is False:
        scope_line = f"NOT allowed by {scope.get('file')}: {scope.get('reason')}"
    else:
        scope_line = str(scope.get("reason") or "no scope file supplied")
    lines = [
        f"# Bounded hunter — {card.id}",
        "",
        "You are one bounded hunter in an authorized black-box assessment.",
        "Work from HTTP responses only. Never read target source code, a target repository,",
        "a local checkout, a container filesystem or a backup of the application.",
        "",
        "## Authorization context",
        "",
        f"- Target: {target}",
        f"- Scope: {scope_line}",
        f"- Account: {account}",
        f"- Model: {model}",
        f"- Time budget: {timeout_seconds:g} seconds",
        f"- Request budget: at most {max_requests} requests",
        "",
        "## Hard rules",
        "",
        "- Stay on the target origin; never follow a redirect to another host.",
        "- Read-only probes unless the card explicitly approves a benign write; no brute force and no denial of service.",
        "- Change one variable per request and keep a benign control where practical.",
        "- A candidate is not a confirmed finding. Report what you observed, not what may be.",
        "- Stop at the first reproducible proof or when the request/time budget is spent.",
        "",
        "## Prompt card",
        "",
        card_text.rstrip(),
        "",
        "## Output contract",
        "",
        "Return only one JSON object on stdout, with no surrounding prose:",
        "",
        '{"candidates": [{"id": "C-1", "title": "short title", "severity": "low",',
        '  "target": "http://host:port", "entrypoint": "/path?query",',
        '  "root_cause": "short-slug", "principal": "identity label",',
        '  "resource": "thing reached", "description": "what was observed"}]}',
        "",
        'Use "candidates": [] when the card produced no candidate. Never emit "confirmed".',
    ]
    return "\n".join(lines).rstrip() + "\n"


def _parse_json_block(text: str) -> Any:
    """Parse one JSON value, tolerating a fence, prose prefix or trailing prose."""
    body = (text or "").strip()
    if not body:
        raise ValueError("runner produced empty stdout")
    fenced = _FENCE.search(body)
    if fenced:
        body = fenced.group(1).strip()
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        starts = [position for position in (body.find("{"), body.find("[")) if position >= 0]
        if not starts:
            raise ValueError(f"invalid JSON: {exc.msg} at line {exc.lineno}") from exc
        decoder = json.JSONDecoder()
        for position in sorted(starts):
            try:
                value, _ = decoder.raw_decode(body[position:])
            except json.JSONDecodeError:
                continue
            return value
        raise ValueError(f"invalid JSON: {exc.msg} at line {exc.lineno}") from exc


def _event_texts(stdout: str) -> tuple[list[str], int]:
    """Return agent text parts and event count from an OpenCode JSONL stream."""
    texts: list[str] = []
    events = 0
    for raw in (stdout or "").splitlines():
        line = raw.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        part = event.get("part")
        kind = event.get("type")
        if kind not in OPENCODE_EVENTS and not isinstance(part, dict):
            continue
        events += 1
        if kind != "text":
            continue
        text = part.get("text") if isinstance(part, dict) else event.get("text")
        if isinstance(text, str) and text.strip():
            texts.append(text)
    return texts, events


def _looks_like_candidate_payload(data: Any) -> bool:
    if isinstance(data, list):
        return True
    if isinstance(data, dict):
        return any(
            key in data
            for key in ("candidates", "findings", "results", "title", "name", "check")
        )
    return False


def parse_runner_output(stdout: str) -> Any:
    """Extract the candidate JSON from a child's plain or JSONL stdout.

    OpenCode ``--format json`` emits one event per line.  The final agent
    message is the last useful ``text`` part; candidate JSON may be fenced or
    surrounded by prose.  Plain JSON output is still accepted for ``--runner``
    overrides and tests.
    """
    text = (stdout or "").strip()
    if not text:
        raise ValueError("runner produced empty stdout")
    texts, events = _event_texts(text)
    if events:
        for candidate_text in reversed(texts):
            try:
                data = _parse_json_block(candidate_text)
            except ValueError:
                continue
            if _looks_like_candidate_payload(data):
                return data
        if texts:
            try:
                data = _parse_json_block("\n".join(texts))
            except ValueError:
                data = None
            if data is not None and _looks_like_candidate_payload(data):
                return data
        raise ValueError(
            f"runner JSON events contained no candidate JSON ({len(texts)} text part(s))"
        )
    return _parse_json_block(text)


def _candidate_records(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        for key in ("candidates", "findings", "results"):
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return [data] if data else []
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    raise ValueError("runner JSON must be an object or an array")


def _split_target(value: str, fallback_target: str) -> tuple[str, str]:
    target = value or fallback_target
    entrypoint = "/"
    try:
        parsed = urlsplit(target)
    except ValueError:
        return target, entrypoint
    if parsed.scheme and parsed.netloc:
        path = parsed.path or "/"
        return target, f"{path}?{parsed.query}" if parsed.query else path
    return target, entrypoint


def _candidate_text(candidate: dict[str, Any], *names: str) -> str:
    for name in names:
        value = candidate.get(name)
        if isinstance(value, (str, int, float)) and not isinstance(value, bool):
            text = _as_text(value)
            if text:
                return text
    return ""


def normalize_candidates(
    data: Any,
    *,
    prompt_id: str,
    target: str,
    account: str,
    model: str,
) -> list[dict[str, Any]]:
    """Map child candidates onto the ``sak findings import`` candidate shape."""
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(_candidate_records(data), start=1):
        title = _candidate_text(raw, "title", "name", "check", "template")
        if not title:
            title = f"Candidate {index} from {prompt_id}"
        raw_id = _candidate_text(raw, "id")
        candidate_id = raw_id or f"{prompt_id}-C{index:02d}"
        if candidate_id in seen:
            continue
        seen.add(candidate_id)
        raw_target = _candidate_text(raw, "target", "matched-at", "matched_at", "url", "host")
        asset, entrypoint = _split_target(raw_target, target)
        candidate_entry = _candidate_text(raw, "entrypoint", "path") or entrypoint
        severity = _severity(_candidate_text(raw, "severity", "risk"))
        root_cause = _slug(
            _candidate_text(raw, "root_cause", "template-id", "template", "check", "type"),
            _slug(title, "candidate-reported"),
        )
        principal = _candidate_text(raw, "principal", "user", "account") or account
        resource = _candidate_text(raw, "resource", "endpoint") or candidate_entry
        record: dict[str, Any] = {
            "id": candidate_id,
            "prompt": prompt_id,
            "title": title,
            "status": "needs_validation",
            "severity": severity,
            "target": asset,
            "entrypoint": candidate_entry,
            "root_cause": root_cause,
            "principal": principal,
            "resource": resource,
            "source": {"tool": "sak hunt", "prompt": prompt_id, "model": model},
        }
        description = _candidate_text(raw, "description", "summary", "detail", "details")
        if description:
            record["description"] = description
        candidates.append(record)
    return candidates


def hunt_record_path(run_dir: Path, prompt_id: str) -> Path:
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", prompt_id).strip("-._") or "prompt"
    return run_dir / HUNT_DIRNAME / f"{name}.json"


def write_record(run_dir: Path, record: dict[str, Any]) -> Path:
    path = hunt_record_path(run_dir, str(record.get("prompt") or "prompt"))
    util.ensure_directory(path.parent)
    root = run_dir.resolve()
    resolved = path.resolve()
    if root != resolved.parent and root not in resolved.parents:
        raise HuntError(f"refusing to write outside the run directory: {resolved}")
    path.write_text(util.dump_json(record), encoding="utf-8")
    return path


def _truncate(text: str) -> str:
    if len(text) <= MAX_CAPTURE_CHARS:
        return text
    return text[:MAX_CAPTURE_CHARS].rstrip() + f"\n[truncated at {MAX_CAPTURE_CHARS} characters]"


def _record(
    *,
    prompt_id: str,
    title: str,
    target: str,
    model: str,
    command: list[str],
    secrets: list[str],
    scope: dict[str, Any],
    account: str,
    started_at: str,
) -> dict[str, Any]:
    return {
        "schema_version": "1",
        "prompt": prompt_id,
        "title": title,
        "target": target,
        "model": model,
        "account": account,
        "scope": scope,
        "command": sanitize_value(command, secrets),
        "command_line": sanitize_text(shlex.join(command), secrets),
        "prompt_chars": 0,
        "exit": None,
        "duration_seconds": 0.0,
        "status": STATUS_ERROR,
        "timed_out": False,
        "candidates": [],
        "error": None,
        "started_at": started_at,
        "finished_at": None,
        "stdout": "",
        "stderr": "",
    }


def run_one_hunter(
    card: Any,
    *,
    target: str,
    model: str,
    command: list[str],
    timeout_seconds: float,
    deadline: float,
    secrets: list[str],
    scope: dict[str, Any],
    account: str,
) -> dict[str, Any]:
    """Launch one child hunter and return its sanitized record."""
    started_at = _now()
    record = _record(
        prompt_id=card.id,
        title=_as_text(card.data.get("title")) or card.id,
        target=target,
        model=model,
        command=command,
        secrets=secrets,
        scope=scope,
        account=account,
        started_at=started_at,
    )
    if scope.get("allowed") is False:
        record["error"] = f"target not authorized: {scope.get('reason')}"
        record["finished_at"] = _now()
        return record

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        record["error"] = "total time budget exhausted before the hunter started"
        record["finished_at"] = _now()
        return record
    limit = max(0.1, min(timeout_seconds, remaining))
    prompt = render_hunter_prompt(
        card,
        target=target,
        scope=scope,
        account=account,
        model=model,
        timeout_seconds=limit,
    )
    record["prompt_chars"] = len(prompt)
    started = time.monotonic()
    process: subprocess.Popen[str] | None = None
    invocation = [*command, prompt]
    try:
        process = subprocess.Popen(
            invocation,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        stdout, stderr = process.communicate(timeout=limit)
    except subprocess.TimeoutExpired:
        if process is not None:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except OSError:
                process.kill()
            stdout, stderr = process.communicate()
        else:  # pragma: no cover - Popen raised before assignment
            stdout, stderr = "", ""
        record.update(
            {
                "timed_out": True,
                "status": STATUS_ERROR,
                "error": f"timeout after {limit:g}s",
                "stdout": _truncate(sanitize_text(stdout, secrets)),
                "stderr": _truncate(sanitize_text(stderr, secrets)),
                "duration_seconds": round(time.monotonic() - started, 3),
                "finished_at": _now(),
            }
        )
        return record
    except OSError as exc:
        record.update(
            {
                "status": STATUS_ERROR,
                "error": f"cannot start runner: {exc}",
                "duration_seconds": round(time.monotonic() - started, 3),
                "finished_at": _now(),
            }
        )
        return record

    duration = round(time.monotonic() - started, 3)
    record["exit"] = process.returncode
    record["duration_seconds"] = duration
    record["stdout"] = _truncate(sanitize_text(stdout, secrets))
    record["stderr"] = _truncate(sanitize_text(stderr, secrets))
    record["finished_at"] = _now()
    if process.returncode != 0:
        record["status"] = STATUS_ERROR
        record["error"] = f"runner exited with code {process.returncode}"
        return record
    try:
        data = parse_runner_output(stdout)
        candidates = normalize_candidates(
            data,
            prompt_id=card.id,
            target=target,
            account=account,
            model=model,
        )
    except ValueError as exc:
        record["status"] = STATUS_ERROR
        record["error"] = str(exc)
        return record
    record["status"] = STATUS_SUCCESS
    record["candidates"] = sanitize_value(candidates, secrets)
    return record


def run_hunt(
    *,
    run_id: str | Path,
    target: str,
    prompt_ids: Sequence[str],
    catalog: str | Path = prompts_module.DEFAULT_CATALOG,
    max_agents: int = DEFAULT_MAX_AGENTS,
    model: str = DEFAULT_MODEL,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    runner: str | None = None,
) -> dict[str, Any]:
    """Run the bounded hunter set and write one sanitized record per prompt."""
    if not str(target).strip():
        raise HuntError("--target is required")
    if max_agents < 1 or max_agents > MAX_AGENTS:
        raise HuntError(f"--max-agents must be between 1 and {MAX_AGENTS}")
    if timeout_seconds <= 0:
        raise HuntError("--timeout must be greater than zero")
    if len(prompt_ids) > MAX_PROMPTS:
        raise HuntError(
            f"prompt budget exceeded: {len(prompt_ids)} ids requested, at most {MAX_PROMPTS} allowed"
        )
    cards = load_hunt_cards(catalog, prompt_ids)
    run_dir = resolve_run_dir(run_id)
    util.ensure_directory(run_dir)
    secrets = _secret_values()
    scope = scope_context(run_dir, target)
    account = sanitize_text(_account_label(), secrets)
    command = runner_command(runner, model)

    started = time.monotonic()
    waves = max(1, math.ceil(len(cards) / max_agents))
    deadline = started + (timeout_seconds * waves)

    # Import locally so a thread-pool failure cannot take down the CLI import path.
    from concurrent.futures import ThreadPoolExecutor

    records: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(max_agents, len(cards))) as pool:
        futures = [
            pool.submit(
                run_one_hunter,
                card,
                target=target,
                model=model,
                command=command,
                timeout_seconds=timeout_seconds,
                deadline=deadline,
                secrets=secrets,
                scope=scope,
                account=account,
            )
            for card in cards
        ]
        for future in futures:
            records.append(future.result())

    for record in records:
        write_record(run_dir, record)

    results = [
        {
            "prompt": record["prompt"],
            "status": record["status"],
            "exit": record["exit"],
            "duration_seconds": record["duration_seconds"],
            "candidates": len(record["candidates"]),
            "error": record["error"],
            "record": str(hunt_record_path(run_dir, record["prompt"])),
        }
        for record in records
    ]
    counts = {
        "prompts": len(records),
        "success": sum(1 for record in records if record["status"] == STATUS_SUCCESS),
        "errors": sum(1 for record in records if record["status"] != STATUS_SUCCESS),
        "candidates": sum(len(record["candidates"]) for record in records),
    }
    summary: dict[str, Any] = {
        "run": str(run_dir),
        "target": target,
        "model": model,
        "runner": sanitize_text(shlex.join(command), secrets),
        "max_agents": max_agents,
        "timeout_seconds": timeout_seconds,
        "total_seconds": round(time.monotonic() - started, 3),
        "scope": scope,
        "counts": counts,
        "ok": counts["errors"] == 0,
        "results": results,
    }
    return sanitize_value(summary, secrets)


def handle(args: argparse.Namespace) -> int:
    summary = run_hunt(
        run_id=args.run,
        target=args.target,
        prompt_ids=parse_prompt_ids(args.prompts),
        catalog=args.catalog,
        max_agents=args.max_agents,
        model=args.model,
        timeout_seconds=args.timeout,
        runner=args.runner,
    )
    if args.json:
        util.emit_json(summary)
    else:
        rows = [
            [
                result["prompt"],
                result["status"],
                result["exit"],
                result["duration_seconds"],
                result["candidates"],
                result["error"],
            ]
            for result in summary["results"]
        ]
        print(util.table(rows, ["PROMPT", "STATUS", "EXIT", "SECONDS", "CANDIDATES", "ERROR"]))
        counts = summary["counts"]
        print(
            f"{counts['success']}/{counts['prompts']} hunter(s) succeeded, "
            f"{counts['candidates']} candidate(s); records under "
            f"{Path(summary['run']) / HUNT_DIRNAME}"
        )
    return 0 if summary["ok"] else 1


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    """Register the ``sak hunt`` command with a parent parser."""
    parser = subparsers.add_parser("hunt", help="run bounded prompt-card hunters")
    parser.add_argument("--run", required=True, help="run name or directory (bare names live under runs/)")
    parser.add_argument("--target", required=True, help="authorized target URL")
    parser.add_argument("--prompts", required=True, help="comma-separated prompt card ids")
    parser.add_argument(
        "--max-agents",
        type=int,
        default=DEFAULT_MAX_AGENTS,
        help=f"concurrent hunters (default: {DEFAULT_MAX_AGENTS}, max: {MAX_AGENTS})",
    )
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"child model (default: {DEFAULT_MODEL})")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"per-hunter timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS:g})",
    )
    parser.add_argument(
        "--runner",
        help="runner command; the rendered prompt is appended as the final argument "
        "(default: opencode run --standalone --format json --model MODEL)",
    )
    parser.add_argument(
        "--catalog",
        default=prompts_module.DEFAULT_CATALOG,
        help=f"prompt catalog directory (default: {prompts_module.DEFAULT_CATALOG})",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.set_defaults(func=handle)


def main(argv: Sequence[str] | None = None) -> int:
    """Standalone entry point: ``python -m sak.hunt`` or the ``hunt`` subcommand."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] != "hunt":
        arguments.insert(0, "hunt")
    parser = argparse.ArgumentParser(
        prog="sak hunt",
        description="Run bounded prompt-card hunters against an authorized target.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    add_parser(subparsers)
    args = parser.parse_args(arguments)
    try:
        return int(args.func(args))
    except util.SakError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
