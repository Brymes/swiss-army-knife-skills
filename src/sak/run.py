"""Step runner: turn one planned step into a gated adapter run.

The runner loads ``plan.json`` from the run directory, resolves the step to a catalog
adapter, checks the ``scope.md`` allowlist and the run's request/time budget, then either
prints a dry-run command or executes it and writes masked logs plus parsed findings.

Nothing here assumes authorization: a dry run is offline and may print a command without a
scope file, but ``--execute`` refuses unless the target host and port are listed in
``scope.md`` and the step came from the plan.
"""

from __future__ import annotations

import argparse
import importlib.util
import ipaddress
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import catalog as catalog_module
from . import util

SCOPE_FILENAME = "scope.md"
PLAN_FILENAME = "plan.json"
BUDGET_FILENAME = "budget.json"
DEFAULT_MAX_REQUESTS = 2000
DEFAULT_MAX_SECONDS = 300
_BUDGET_KEYS = {
    "max_requests": "max_requests",
    "requests": "max_requests",
    "request_budget": "max_requests",
    "max_seconds": "max_seconds",
    "seconds": "max_seconds",
    "time_budget": "max_seconds",
    "timeout_seconds": "max_seconds",
}
# Only these headings may authorize a host.  Exclusion, notes and unknown headings never do.
_POSITIVE_SECTIONS = re.compile(
    r"^(allowed hosts?|allowed targets?|allow ?list|in[- ]scope( hosts?)?|"
    r"authori[sz]ed hosts?|scope( hosts?)?|targets?|hosts?)$"
)
_NEGATIVE_SECTIONS = re.compile(
    r"^(out[- ]of[- ]scope|exclusions?|excluded( hosts?)?|deny( list)?|denied|"
    r"forbidden|do not test|not allowed)$"
)
_BUDGET_SECTIONS = re.compile(r"^(budget|limits?|quotas?)$")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)


class RunError(util.SakError):
    """Raised when a run cannot be prepared from the plan, scope or options."""


@dataclass(frozen=True)
class Scope:
    """A parsed ``scope.md`` allowlist. Absent, empty or invalid means default deny."""

    path: Path | None
    hosts: tuple[str, ...] = ()
    excluded: tuple[str, ...] = ()
    max_requests: int | None = None
    max_seconds: int | None = None
    errors: tuple[str, ...] = ()

    @property
    def present(self) -> bool:
        return self.path is not None

    def as_dict(self) -> dict[str, Any]:
        return {
            "file": str(self.path) if self.path is not None else None,
            "present": self.present,
            "hosts": list(self.hosts),
            "excluded": list(self.excluded),
            "errors": list(self.errors),
            "max_requests": self.max_requests,
            "max_seconds": self.max_seconds,
        }


def adapters_dir() -> Path:
    override = os.environ.get("SAK_ADAPTERS")
    if override:
        return Path(override).expanduser()
    return util.repo_root() / "adapters"


def load_adapter(name: str) -> Any:
    """Load ``adapters/<name>.py`` by path so the package stays dependency-free."""
    if not re.fullmatch(r"[a-z][a-z0-9_]*", str(name or "")):
        raise RunError(f"invalid adapter name {name!r}")
    path = adapters_dir() / f"{name}.py"
    if not path.is_file():
        raise RunError(f"no adapter module {name!r} at {path}")
    module_name = f"sak_adapter_{name}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RunError(f"cannot load adapter module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    for attribute in ("check", "build", "execute", "parse"):
        if not hasattr(module, attribute):
            raise RunError(f"adapter {name!r} does not provide {attribute}()")
    return module


def _host_is_valid(host: str) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOSTNAME.fullmatch(host))


def _parse_entry(entry: str) -> tuple[str | None, str | None]:
    """Return ``(host[:port], error)`` for one allowlist bullet.

    Ambiguous or malformed syntax is an error, never a broader rule: wildcards, CIDR
    ranges, userinfo, query strings and non-HTTP schemes are rejected.
    """
    text = entry.strip().strip("`").strip()
    text = text.split("#", 1)[0].strip()
    if not text:
        return None, "empty host entry"
    if any(character.isspace() for character in text):
        return None, f"whitespace in host entry {entry!r}"
    port: int | None = None
    if "://" in text:
        parts = urlsplit(text)
        if parts.scheme.lower() not in {"http", "https"}:
            return None, f"unsupported scheme in {entry!r}"
        if parts.username or parts.password or parts.query or parts.fragment:
            return None, f"ambiguous URL in {entry!r}; use scheme://host[:port] only"
        host = (parts.hostname or "").lower()
        try:
            port = parts.port
        except ValueError:
            return None, f"invalid port in {entry!r}"
    elif text.startswith("["):
        match = re.fullmatch(r"\[([0-9A-Fa-f:.]+)\](?::(\d{1,5}))?", text)
        if match is None:
            return None, f"invalid IPv6 host entry {entry!r}"
        host = match.group(1).lower()
        if match.group(2) is not None:
            port = int(match.group(2))
    else:
        if text.count(":") > 1:
            return None, f"ambiguous host:port {entry!r}; bracket IPv6 literals"
        host, separator, raw_port = text.partition(":")
        host = host.lower()
        if separator:
            if not raw_port.isdigit():
                return None, f"invalid port in {entry!r}"
            port = int(raw_port)
    if not _host_is_valid(host):
        return None, f"invalid host {host!r} in {entry!r}"
    if port is not None and not 1 <= port <= 65535:
        return None, f"port out of range in {entry!r}"
    display = f"[{host}]" if ":" in host else host
    return (f"{display}:{port}" if port is not None else display), None


def _section(heading: str) -> str:
    return re.sub(r"\s+", " ", heading.strip().lower()).strip(" :")


def _table_cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def _is_table_separator(cells: list[str]) -> bool:
    meaningful = [cell for cell in cells if cell]
    return bool(meaningful) and all(re.fullmatch(r":?-{2,}:?", cell) for cell in meaningful)


def _non_host_asset(asset: str, kind: str = "") -> bool:
    """True for path, repository or source/binary rows: they are not host destinations."""
    text = asset.strip()
    return text.startswith("/") or "@" in text or kind.strip().lower() in {"source", "binary"}


def parse_scope_text(text: str, *, path: Path | None = None) -> Scope:
    """Parse the documented ``scope.md`` bullets and tables into a strict allowlist.

    Only explicit positive sections authorize hosts.  Exclusion sections deny, and notes,
    forbidden-action or unknown sections are ignored, so they can never widen the scope.
    The ``In scope`` Markdown table used by the reviewed scope template is supported: the
    Asset column is parsed and path/repository/source rows are ignored because the host gate
    cannot enforce them.  Malformed host entries are collected as errors and make execute
    refuse rather than guess.
    """
    hosts: list[str] = []
    excluded: list[str] = []
    errors: list[str] = []
    max_requests: int | None = None
    max_seconds: int | None = None
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        heading = re.match(r"^#{1,6}\s+(.*)$", line)
        if heading:
            section = _section(heading.group(1))
            continue
        positive = _POSITIVE_SECTIONS.fullmatch(section)
        negative = _NEGATIVE_SECTIONS.fullmatch(section)

        if line.startswith("|"):
            cells = _table_cells(line)
            if not cells or cells[0].strip().lower() in {"asset", "host", "hosts", "target", "targets"}:
                continue
            if _is_table_separator(cells):
                continue
            asset = cells[0]
            kind = cells[1] if len(cells) > 1 else ""
            if positive:
                entry, error = _parse_entry(asset)
                if error is None:
                    if entry not in hosts:
                        hosts.append(entry)
                elif not _non_host_asset(asset, kind):
                    errors.append(error)
            elif negative:
                entry, error = _parse_entry(asset)
                if error is None and entry not in excluded:
                    excluded.append(entry)
            continue

        if not line.startswith(("- ", "* ", "+ ")):
            continue
        item = line[2:].strip()
        if not item:
            continue
        budget = re.match(r"^([A-Za-z_]+)\s*[:=]\s*(\d+)\s*$", item)
        if _BUDGET_SECTIONS.fullmatch(section):
            if budget is not None and _BUDGET_KEYS.get(budget.group(1).lower()):
                key = _BUDGET_KEYS[budget.group(1).lower()]
                value = int(budget.group(2))
                if key == "max_requests":
                    max_requests = value if max_requests is None else min(max_requests, value)
                else:
                    max_seconds = value if max_seconds is None else min(max_seconds, value)
            elif re.match(r"^[A-Za-z_]+\s*[:=]", item):
                errors.append(f"unexpected budget bullet {item!r}")
            continue
        if budget and _BUDGET_KEYS.get(budget.group(1).lower()):
            errors.append(f"budget key {budget.group(1)!r} outside a budget section")
            continue
        if positive:
            entry, error = _parse_entry(item)
            if error:
                errors.append(error)
            elif entry not in hosts:
                hosts.append(entry)
            continue
        if negative:
            entry, error = _parse_entry(item)
            if error:
                if not _non_host_asset(item) and " " not in item:
                    errors.append(error)
                continue
            if entry not in excluded:
                excluded.append(entry)
            continue
        # Notes, forbidden actions and unknown sections never authorize anything.
    return Scope(
        path=path,
        hosts=tuple(hosts),
        excluded=tuple(excluded),
        max_requests=max_requests,
        max_seconds=max_seconds,
        errors=tuple(errors),
    )


def load_scope(run_dir: str | Path) -> Scope:
    path = Path(run_dir).expanduser() / SCOPE_FILENAME
    if not path.is_file():
        return Scope(path=None)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RunError(f"cannot read {path}: {exc}") from exc
    return parse_scope_text(text, path=path)


def target_host_port(target: str) -> tuple[str, int | None]:
    text = str(target or "").strip()
    if not text:
        return "", None
    if "://" in text:
        parts = urlsplit(text)
    elif text.startswith("//"):
        parts = urlsplit(f"http:{text}")
    else:
        parts = urlsplit(f"//{text}")
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is None:
        port = {"http": 80, "https": 443}.get(parts.scheme.lower())
    return host, port


def _split_entry(entry: str) -> tuple[str, int | None]:
    if entry.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\](?::(\d+))?", entry)
        if match is not None:
            return match.group(1), int(match.group(2)) if match.group(2) else None
    host, _, port = entry.rpartition(":")
    if host and port.isdigit():
        return host, int(port)
    return entry, None


def _entry_matches(entry: str, host: str, port: int | None) -> bool:
    entry_host, entry_port = _split_entry(entry)
    if entry_host != host:
        return False
    if entry_port is None:
        return True
    return port is not None and entry_port == port


def scope_allows(scope: Scope, target: str) -> tuple[bool, str]:
    """Default deny: exact host match, with the port checked when the entry names one."""
    host, port = target_host_port(target)
    if not host:
        return False, f"target {target!r} has no host"
    if scope.errors:
        return False, f"{SCOPE_FILENAME} has invalid entries: {scope.errors[0]}"
    if not scope.hosts:
        if not scope.present:
            return False, f"no {SCOPE_FILENAME} in the run directory"
        return False, f"{SCOPE_FILENAME} has no allowed hosts (default deny)"
    shown = f"{host}:{port}" if port is not None else host
    for entry in scope.excluded:
        if _entry_matches(entry, host, port):
            return False, f"{shown} is explicitly excluded by {SCOPE_FILENAME}"
    for entry in scope.hosts:
        if _entry_matches(entry, host, port):
            return True, f"{shown} allowed by {entry}"
    return False, f"{shown} is not in the {SCOPE_FILENAME} allowlist"


def load_plan(run_dir: str | Path) -> tuple[dict[str, Any] | None, list[str]]:
    path = Path(run_dir).expanduser() / PLAN_FILENAME
    if not path.is_file():
        return None, [
            f"no {PLAN_FILENAME} under {Path(run_dir)}; the step was resolved from the catalog "
            "and execute is disabled"
        ]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RunError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RunError(f"{path} must contain a plan object")
    return data, []


def resolve_step(
    catalog: catalog_module.Catalog,
    plan: dict[str, Any] | None,
    step_id: str,
) -> dict[str, Any]:
    candidate: dict[str, Any] | None = None
    if plan is not None:
        for item in plan.get("candidates") or []:
            if isinstance(item, dict) and item.get("id") == step_id:
                candidate = dict(item)
                break
        if candidate is None:
            known = ", ".join(
                str(item.get("id")) for item in plan.get("candidates") or [] if isinstance(item, dict)
            ) or "none"
            raise RunError(f"step {step_id!r} is not a candidate in {PLAN_FILENAME} (known: {known})")

    card = None
    if step_id in catalog.ids("tool"):
        card = catalog.find(step_id)
    if candidate is None and card is None:
        raise RunError(f"unknown step {step_id!r}: not in the plan and not a catalog tool card")
    step = candidate or {"id": step_id}
    adapter = step.get("adapter") or (card.data.get("adapter") if card is not None else None)
    if not adapter:
        raise RunError(f"step {step_id!r} has no adapter in its catalog card")
    step["adapter"] = str(adapter)
    if card is not None and "card" not in step:
        step["card"] = card.data
    return step


def _read_budget(run_dir: Path) -> dict[str, Any]:
    path = run_dir / BUDGET_FILENAME
    if not path.is_file():
        return {"requests": 0, "seconds": 0.0, "steps": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RunError(f"cannot read budget file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RunError(f"budget file {path} must contain an object")
    data.setdefault("requests", 0)
    data.setdefault("seconds", 0.0)
    data.setdefault("steps", [])
    return data


def plan_budget(
    scope: Scope,
    step: dict[str, Any],
    adapter: Any,
    spent: dict[str, Any],
) -> dict[str, Any]:
    """Clip the wall clock so the adapter's worst-case estimate fits the request budget."""
    max_requests = scope.max_requests if scope.max_requests is not None else DEFAULT_MAX_REQUESTS
    max_seconds = scope.max_seconds if scope.max_seconds is not None else DEFAULT_MAX_SECONDS
    spent_requests = int(spent.get("requests") or 0)
    spent_seconds = float(spent.get("seconds") or 0.0)
    remaining_requests = max(0, max_requests - spent_requests)
    remaining_seconds = max(0, int(max_seconds - spent_seconds))
    estimate = 0
    if hasattr(adapter, "estimate_requests"):
        estimate = int(adapter.estimate_requests(step, remaining_seconds) or 0)
    effective_seconds = remaining_seconds
    if estimate > remaining_requests and estimate > 0 and remaining_seconds > 0:
        effective_seconds = max(1, (remaining_seconds * remaining_requests) // estimate)
        estimate = int(adapter.estimate_requests(step, effective_seconds) or 0)
    return {
        "max_requests": max_requests,
        "max_seconds": max_seconds,
        "spent_requests": spent_requests,
        "spent_seconds": round(spent_seconds, 3),
        "remaining_requests": remaining_requests,
        "remaining_seconds": remaining_seconds,
        "estimated_requests": estimate,
        "effective_timeout_seconds": effective_seconds,
        "exceeded": remaining_requests <= 0 or remaining_seconds <= 0 or estimate > remaining_requests,
    }


def _secret_values() -> list[str]:
    return util.secret_env_values(dict(os.environ))


def _mask(value: str | None, secrets: list[str] | None = None) -> str:
    return util.mask_secrets(value, secrets if secrets is not None else _secret_values())


def _sanitize(value: Any, secrets: list[str]) -> Any:
    """Redact a nested JSON-like value before it is returned or written to disk."""
    if isinstance(value, str):
        return util.mask_secrets(value, secrets)
    if isinstance(value, dict):
        return {str(key): _sanitize(item, secrets) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize(item, secrets) for item in value]
    return value


def _report_scope(scope: Scope, target: str, *, plan_present: bool) -> dict[str, Any]:
    report = scope.as_dict()
    if not plan_present:
        report.update({"allowed": False, "reason": f"no {PLAN_FILENAME} target to check"})
        return report
    allowed, reason = scope_allows(scope, target)
    report.update({"allowed": allowed, "reason": reason})
    return report


def _tool_report(check: dict[str, Any]) -> dict[str, Any]:
    return {
        "available": bool(check.get("available")),
        "binary": check.get("binary"),
        "version": check.get("version"),
        "missing": list(check.get("missing") or []),
        "hints": list(check.get("hints") or []),
        "notes": list(check.get("notes") or []),
        "license_notice": check.get("license_notice"),
        "api_key_present": check.get("api_key_present"),
        "provider": check.get("provider"),
        "mcp_example": check.get("mcp_example"),
    }


def _warnings(
    check: dict[str, Any],
    scope: Scope,
    plan_present: bool,
    execute: bool,
    policy: str = "target",
) -> list[str]:
    warnings: list[str] = []
    if not plan_present:
        warnings.append(f"no {PLAN_FILENAME}; using the catalog card and a placeholder target")
    if not check.get("available"):
        warnings.append(f"missing tool: {', '.join(check.get('missing') or ['unknown'])}")
    if scope.errors:
        warnings.append(f"{SCOPE_FILENAME} has invalid entries; execute runs will refuse")
    if not scope.present:
        warnings.append(f"no {SCOPE_FILENAME}; execute runs will refuse")
    elif not scope.hosts:
        warnings.append(f"{SCOPE_FILENAME} lists no allowed hosts; execute runs will refuse")
    if policy != "target":
        warnings.append(
            f"execute disabled: destination policy {policy!r} cannot be authorized by {SCOPE_FILENAME}"
        )
    if check.get("api_key_present") is False:
        warnings.append("no provider API key; dry runs are unaffected")
    if not execute:
        warnings.append("dry run: no command was executed and no target was contacted")
    return warnings


def run_step(
    run_dir: str | Path,
    step_id: str,
    *,
    execute: bool = False,
    catalog_path: str | Path = "catalog",
) -> dict[str, Any]:
    """Prepare (and optionally execute) one step, returning a serializable report."""
    run_dir = Path(run_dir).expanduser()
    loaded = catalog_module.load_catalog(catalog_path)
    plan, warnings = load_plan(run_dir)
    step = resolve_step(loaded, plan, step_id)
    adapter = load_adapter(step["adapter"])
    check = adapter.check()
    scope = load_scope(run_dir)
    plan_present = plan is not None
    target = str(plan.get("target")) if plan_present and plan.get("target") else f"<target for {step_id}>"
    policy = str(getattr(adapter, "DESTINATION_POLICY", "target"))
    secrets = _secret_values()

    report: dict[str, Any] = {
        "step": step_id,
        "adapter": step["adapter"],
        "dry_run": not execute,
        "run_dir": str(run_dir),
        "target": _sanitize(target, secrets),
        "plan": str(run_dir / PLAN_FILENAME) if plan_present else None,
        "scope": _report_scope(scope, target, plan_present=plan_present),
        "destination": {"policy": policy, "enforceable": policy == "target"},
        "tool": _tool_report(check),
        "warnings": warnings,
    }

    try:
        built = adapter.build(step, target, run_dir=run_dir)
    except ValueError as exc:
        raise RunError(f"invalid {step['adapter']} step options: {exc}") from exc

    budget = plan_budget(scope, step, adapter, _read_budget(run_dir))
    report["budget"] = {
        **budget,
        "enforced": execute,
        "estimate_note": "adapter worst-case estimate; requests are not counted by the tool",
    }
    report["command"] = [_sanitize(str(part), secrets) for part in built.get("command") or []]
    report["display"] = _mask(str(built.get("display") or " ".join(report["command"])), secrets)
    report["notes"] = _sanitize(list(built.get("notes") or []), secrets)
    report["requires_scope"] = bool(built.get("requires_scope", True))
    report["findings"] = []
    report["artifacts"] = {}

    if not execute:
        report["ok"] = True
        report["warnings"] = _warnings(check, scope, plan_present, execute=False, policy=policy)
        return report

    if not plan_present:
        return _refused(report, f"execute needs {PLAN_FILENAME} in {run_dir}; run `sak plan --run-dir` first")
    if not scope.present:
        return _refused(report, f"execute needs {SCOPE_FILENAME} in {run_dir} naming the allowed hosts")
    if not report["scope"]["allowed"]:
        return _refused(report, f"scope refusal: {report['scope']['reason']}")
    if policy != "target":
        report["warnings"] = _warnings(check, scope, plan_present, execute=True, policy=policy)
        return _refused(
            report,
            str(
                getattr(
                    adapter,
                    "DESTINATION_REFUSAL",
                    f"adapter destination policy {policy!r} cannot be authorized by {SCOPE_FILENAME}",
                )
            ),
        )
    if not check.get("available"):
        report["warnings"] = _warnings(check, scope, plan_present, execute=True, policy=policy)
        return _refused(
            report,
            f"missing tool for {step_id}: {', '.join(check.get('missing') or ['unknown'])}",
            hints=list(check.get("hints") or []),
        )
    if budget["exceeded"]:
        return _refused(
            report,
            "budget refusal: "
            f"estimate {budget['estimated_requests']} requests / {budget['effective_timeout_seconds']}s "
            f"exceeds remaining {budget['remaining_requests']} requests / "
            f"{budget['remaining_seconds']}s",
        )

    for name in ("logs", "steps", "findings"):
        util.ensure_directory(run_dir / name)

    started = _now()
    try:
        result = adapter.execute(
            step,
            target,
            timeout=int(budget["effective_timeout_seconds"]),
            run_dir=run_dir,
        )
    except ValueError as exc:
        raise RunError(f"invalid {step['adapter']} step options: {exc}") from exc

    elapsed = float(result.get("duration_seconds") or 0.0)
    report["executed_at"] = started
    report["returncode"] = result.get("returncode")
    report["timed_out"] = bool(result.get("timed_out"))
    report["duration_seconds"] = elapsed
    report["usage"] = _sanitize(result.get("usage") or {}, secrets)
    report["findings"] = _sanitize(list(result.get("findings") or []), secrets)
    report["stdout"] = ""
    report["stderr"] = ""
    if result.get("parse_error"):
        report["parse_error"] = _sanitize(str(result["parse_error"]), secrets)
    if result.get("refused"):
        report["warnings"] = _warnings(check, scope, plan_present, execute=True, policy=policy)
        return _refused(report, str(result.get("reason") or "adapter refused"), hints=list(result.get("hints") or []))

    masked_stdout = _mask(result.get("stdout"), secrets)
    masked_stderr = _mask(result.get("stderr"), secrets)
    log_path = run_dir / "logs" / f"{step_id}.log"
    log_path.write_text(
        f"# sak run {step_id}\n"
        f"adapter: {step['adapter']}\n"
        f"command: {report['display']}\n"
        f"returncode: {report['returncode']} (timed_out={report['timed_out']})\n"
        f"duration_seconds: {elapsed}\n"
        f"scope: {report['scope']['reason']}\n"
        f"destination_policy: {policy}\n"
        f"\n## stdout\n{masked_stdout}\n"
        f"\n## stderr\n{masked_stderr}\n",
        encoding="utf-8",
    )
    findings_path = run_dir / "findings" / f"{step_id}.json"
    findings_path.write_text(util.dump_json(report["findings"]), encoding="utf-8")
    record = {
        "step": step_id,
        "adapter": step["adapter"],
        "target": _sanitize(target, secrets),
        "executed_at": report["executed_at"],
        "command": report["command"],
        "returncode": report["returncode"],
        "timed_out": report["timed_out"],
        "duration_seconds": elapsed,
        "findings": len(report["findings"]),
        "usage": report["usage"],
        "budget": budget,
        "destination_policy": policy,
        "parse_error": report.get("parse_error"),
        "license_notice": result.get("license_notice") or check.get("license_notice"),
    }
    steps_path = run_dir / "steps" / f"{step_id}.json"
    steps_path.write_text(util.dump_json(record), encoding="utf-8")
    _update_budget(run_dir, step_id, estimated=budget["estimated_requests"], seconds=elapsed)

    report["artifacts"] = {
        "log": str(log_path),
        "findings": str(findings_path),
        "step": str(steps_path),
    }
    report["ok"] = (
        report["returncode"] == 0
        and not report["timed_out"]
        and not report.get("parse_error")
    )
    return report


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _refused(report: dict[str, Any], reason: str, *, hints: list[str] | None = None) -> dict[str, Any]:
    report["ok"] = False
    report["refused"] = True
    report["reason"] = reason
    if hints:
        report["hints"] = hints
    return report


def _update_budget(run_dir: Path, step_id: str, *, estimated: int, seconds: float) -> None:
    path = run_dir / BUDGET_FILENAME
    spend = _read_budget(run_dir)
    spend["requests"] = int(spend.get("requests") or 0) + int(estimated)
    spend["seconds"] = round(float(spend.get("seconds") or 0.0) + float(seconds), 3)
    entries = spend.setdefault("steps", [])
    if isinstance(entries, list):
        entries.append(
            {
                "step": step_id,
                "requests": int(estimated),
                "seconds": round(float(seconds), 3),
                "at": _now(),
            }
        )
    path.write_text(util.dump_json(spend), encoding="utf-8")


def _print_report(report: dict[str, Any]) -> None:
    if report.get("refused"):
        print(f"refused: {report['reason']}")
        for hint in report.get("hints") or []:
            print(f"  {hint}")
        return
    if report.get("dry_run"):
        print(f"dry run: {report['step']} (adapter {report['adapter']})")
        print(f"target: {report['target']}")
        scope = report["scope"]
        if scope["present"]:
            state = "allowed" if scope["allowed"] else "not allowed"
            print(f"scope: {state} — {scope['reason']}")
        else:
            print("scope: missing — execute runs will refuse")
        tool = report["tool"]
        if tool["available"]:
            print(f"tool: {tool['binary'] or report['adapter']} {tool['version'] or ''}".rstrip())
        else:
            print(f"tool: missing ({', '.join(tool['missing']) or 'unknown'})")
        print(f"  $ {report['display']}")
        for note in report.get("notes") or []:
            print(f"  note: {note}")
        for warning in report.get("warnings") or []:
            print(f"  warning: {warning}")
        print("  pass --execute to run")
        return
    print(f"ran: {report['step']} rc={report.get('returncode')} findings={len(report.get('findings') or [])}")
    if report.get("timed_out"):
        print("  warning: the adapter hit the run time budget and was stopped")
    for key, path in (report.get("artifacts") or {}).items():
        if path:
            print(f"  {key}: {path}")


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "run", help="run one planned step through an adapter (dry run by default)"
    )
    parser.add_argument(
        "--run",
        dest="run_dir",
        required=True,
        help="run directory containing plan.json and scope.md",
    )
    parser.add_argument("--step", required=True, help="plan candidate or catalog tool id")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="print the adapter command (default)")
    mode.add_argument(
        "--execute",
        action="store_true",
        help="enforce scope and budget, then run the adapter",
    )
    parser.add_argument("--catalog", default="catalog", help="catalog directory (default: catalog)")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.set_defaults(func=handle)


def handle(args: argparse.Namespace) -> int:
    report = run_step(
        args.run_dir,
        args.step,
        execute=bool(getattr(args, "execute", False)),
        catalog_path=getattr(args, "catalog", "catalog"),
    )
    if getattr(args, "json", False):
        util.emit_json(report)
    else:
        _print_report(report)
    if report.get("refused"):
        return 2
    return 0 if report.get("ok") else 1


def main(argv: list[str] | None = None) -> int:
    """Standalone entry point: ``python -m sak.run [run] --run DIR --step ID …``."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "run":
        arguments = arguments[1:]
    parser = argparse.ArgumentParser(
        prog="sak run",
        description="Run one planned step through an adapter. Dry run unless --execute is passed.",
    )
    parser.add_argument("--run", dest="run_dir", required=True, help="run directory")
    parser.add_argument("--step", required=True, help="plan candidate or catalog tool id")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="print the command only (default)")
    mode.add_argument("--execute", action="store_true", help="run the adapter after the gates")
    parser.add_argument("--catalog", default="catalog", help="catalog directory (default: catalog)")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.set_defaults(func=handle)
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
