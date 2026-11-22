"""Findings, stable fingerprints, status transitions, dedupe and coverage.

The module is deliberately file based.  It reads and writes the run directory
artifacts (``findings.json``, ``coverage-ledger.json``) and never executes a
tool or contacts a target.  Verdict names follow the Cloudflare
``security-audit`` model: ``confirmed``, ``needs_validation`` and ``rejected``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

from . import util

STATUSES = ("confirmed", "needs_validation", "rejected")
SEVERITIES = ("info", "low", "medium", "high", "critical")
STATUS_PRIORITY = {"confirmed": 3, "needs_validation": 2, "rejected": 1}
FINGERPRINT_FIELDS = ("asset", "entrypoint", "root_cause", "principal", "resource")
ALLOWED_TRANSITIONS = {
    "confirmed": ("needs_validation", "rejected"),
    "needs_validation": ("confirmed", "rejected"),
    "rejected": ("confirmed", "needs_validation"),
}
SCHEMA_FILES = {
    "findings": "finding.schema.json",
    "coverage": "coverage-ledger.schema.json",
    "run": "run-metadata.schema.json",
}
DEFAULT_FINDINGS = "findings.json"
DEFAULT_LEDGER = "coverage-ledger.json"


# --------------------------------------------------------------------------- #
# Timestamps, loading and schema helpers


def _now(now: datetime | str | None = None) -> str:
    if isinstance(now, str):
        return now
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _validator(kind: str):
    from jsonschema import Draft202012Validator, FormatChecker

    path = util.schemas_dir() / SCHEMA_FILES[kind]
    if not path.is_file():
        raise util.SakError(f"schema not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _format_path(parts: Iterable[Any]) -> str:
    rendered = ""
    for part in parts:
        if isinstance(part, int):
            rendered += f"[{part}]"
        else:
            rendered += f".{part}" if rendered else str(part)
    return rendered or "$"


def _issue(identifier: Any, path: str, message: str) -> dict[str, str]:
    return {"id": str(identifier or "<document>"), "path": path, "message": message}


def _read_text(source: str | Path) -> tuple[str, Path | None]:
    if str(source) in ("-", "stdin"):
        return sys.stdin.read(), None
    path = Path(source).expanduser()
    if path.is_dir():
        path = path / DEFAULT_FINDINGS
    if not path.is_file():
        raise util.SakError(f"findings file not found: {path}")
    return path.read_text(encoding="utf-8"), path


def load_document(source: str | Path) -> tuple[dict[str, Any], Path | None]:
    """Load a findings document from JSON, YAML, a directory or stdin."""
    text, path = _read_text(source)
    if path is not None and path.suffix.lower() in (".yaml", ".yml"):
        data = util.load_yaml(path)
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            label = str(path) if path is not None else "stdin"
            raise util.SakError(f"invalid JSON in {label}: {exc}") from exc
    if not isinstance(data, dict):
        raise util.SakError("a findings document must be a JSON object")
    return data, path


def empty_document(run_id: str, *, now: datetime | str | None = None) -> dict[str, Any]:
    return {
        "schema_version": "1",
        "run_id": run_id,
        "generated_at": _now(now),
        "findings": [],
        "dedupe": [],
    }


def empty_ledger(run_id: str, *, now: datetime | str | None = None) -> dict[str, Any]:
    return {
        "schema_version": "1",
        "run_id": run_id,
        "generated_at": _now(now),
        "boundaries": [],
    }


# --------------------------------------------------------------------------- #
# Fingerprints and masking


def _collapse(value: Any) -> str:
    return " ".join(str(value or "").split()).strip()


def _canonical_asset(value: Any) -> str:
    """Normalise scheme and host case; preserve path, query and fragment.

    URL paths and query values are case-sensitive, so only the scheme and
    authority are folded.  Non-URL assets (repository, file or binary paths)
    keep their original case.
    """
    text = _collapse(value)
    parsed = urlsplit(text)
    if parsed.scheme and parsed.netloc:
        return urlunsplit(
            (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path, parsed.query, parsed.fragment)
        )
    return text


def _canonical_opaque(value: Any) -> str:
    """Collapse whitespace but preserve case for opaque identities."""
    return _collapse(value)


def _canonical_root_cause(value: Any) -> str:
    """Root causes are semantic slugs, not identifiers, so fold their case."""
    return _collapse(value).casefold()


_FINGERPRINT_NORMALISERS = {
    "asset": _canonical_asset,
    "entrypoint": _canonical_opaque,
    "root_cause": _canonical_root_cause,
    "principal": _canonical_opaque,
    "resource": _canonical_opaque,
}


def fingerprint(finding: dict[str, Any]) -> str:
    """Return the stable dedupe fingerprint for one finding.

    The fingerprint is SHA-256 over the normalised asset, entrypoint, root
    cause, principal and resource.  Whitespace is collapsed everywhere; URL
    scheme/host and the root-cause slug are case-folded; URL paths, queries,
    entrypoints, principals and resources keep their case because they are
    case-sensitive identities.  Wording, severity, evidence and status are
    intentionally excluded so a second tool reporting the same root cause
    collapses onto the first record.
    """
    parts = [
        _FINGERPRINT_NORMALISERS[field](finding.get(field)) for field in FINGERPRINT_FIELDS
    ]
    payload = json.dumps(parts, ensure_ascii=False, separators=(",", ":"))
    return sha256(payload.encode("utf-8")).hexdigest()


def fingerprint_for(
    asset: str,
    entrypoint: str,
    root_cause: str,
    principal: str,
    resource: str,
) -> str:
    return fingerprint(
        {
            "asset": asset,
            "entrypoint": entrypoint,
            "root_cause": root_cause,
            "principal": principal,
            "resource": resource,
        }
    )


def assign_fingerprints(document: dict[str, Any]) -> dict[str, Any]:
    """Set every finding's fingerprint to the current computed value."""
    for finding in _as_list(document.get("findings")):
        if isinstance(finding, dict):
            finding["fingerprint"] = fingerprint(finding)
    return document


_EXTRA_SECRETS = (
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
)


def mask_text(text: str | None, secrets: Iterable[str] = ()) -> str:
    """Mask known secret values plus common headers, keys and token formats.

    Masking is for display and reports only.  Stored evidence is never
    rewritten: the raw observation must stay immutable.
    """
    masked = util.mask_secrets(text, secrets)
    for pattern in _EXTRA_SECRETS:
        masked = pattern.sub("***", masked)
    return masked


# --------------------------------------------------------------------------- #
# Evidence metadata


def sha256_file(path: str | Path) -> str:
    digest = sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _evidence_id(path: Path, digest: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", path.stem).strip("-.")
    return f"E-{stem[:32] or 'evidence'}-{digest[:8]}"


def evidence_from_file(
    path: str | Path,
    *,
    kind: str = "observed",
    producer: str = "sak",
    base_dir: str | Path | None = None,
    timestamp: datetime | str | None = None,
    description: str | None = None,
    evidence_id: str | None = None,
) -> dict[str, Any]:
    """Build one evidence record with path, SHA-256, timestamp and producer."""
    given = str(path)
    resolved = Path(given).expanduser()
    if not resolved.is_absolute() and base_dir is not None:
        resolved = Path(base_dir).expanduser() / resolved
    if not resolved.is_file():
        raise util.SakError(f"evidence file not found: {resolved}")
    digest = sha256_file(resolved)
    record: dict[str, Any] = {
        "id": evidence_id or _evidence_id(Path(given), digest),
        "kind": kind,
        "path": Path(given).as_posix(),
        "sha256": digest,
        "timestamp": _now(timestamp),
        "producer": producer or "sak",
    }
    if description:
        record["description"] = description
    return record


def _enrich_evidence(finding: dict[str, Any], *, base_dir: Path, producer: str) -> None:
    for position, evidence in enumerate(_as_list(finding.get("evidence"))):
        if not isinstance(evidence, dict):
            continue
        path = evidence.get("path")
        if not path:
            continue
        resolved = Path(str(path)).expanduser()
        if not resolved.is_absolute():
            resolved = base_dir / resolved
        if not resolved.is_file():
            raise util.SakError(
                f"{finding.get('id', '<finding>')} evidence {position}: file not found: {resolved}"
            )
        digest = sha256_file(resolved)
        evidence.setdefault("sha256", digest)
        evidence.setdefault("id", _evidence_id(Path(str(path)), digest))
        evidence.setdefault("timestamp", _now())
        evidence.setdefault("producer", producer)
        evidence.setdefault("kind", "observed")


# --------------------------------------------------------------------------- #
# Validation


def _as_list(value: Any) -> list[Any]:
    """Return a list only when the value is one; schema errors cover the rest."""
    return value if isinstance(value, list) else []


def _history_issues(finding: dict[str, Any]) -> list[dict[str, str]]:
    identifier = finding.get("id", "<finding>")
    issues: list[dict[str, str]] = []
    previous = None
    history = finding.get("status_history")
    if history is None:
        return issues
    if not isinstance(history, list):
        # The schema validator already reports the wrong type; never iterate it.
        return issues
    for index, item in enumerate(history):
        if not isinstance(item, dict):
            continue
        source, target = item.get("from"), item.get("to")
        path = f"status_history[{index}]"
        if source in STATUSES and target in STATUSES:
            if source == target:
                issues.append(_issue(identifier, path, f"self transition {source} -> {target} is not meaningful"))
            elif target not in ALLOWED_TRANSITIONS[source]:
                allowed = ", ".join(ALLOWED_TRANSITIONS[source])
                issues.append(
                    _issue(identifier, path, f"invalid status transition {source} -> {target}; allowed: {allowed}")
                )
        if previous is not None and source != previous:
            issues.append(
                _issue(identifier, path, f"history is not contiguous: expected from {previous!r}, got {source!r}")
            )
        previous = target
    if previous is not None and previous != finding.get("status"):
        issues.append(
            _issue(
                identifier,
                "status_history",
                f"history ends at {previous!r} but status is {finding.get('status')!r}",
            )
        )
    return issues


def validate_document(
    document: Any,
    *,
    source: str = "findings",
    base_dir: str | Path | None = None,
    check_files: bool = True,
) -> list[dict[str, str]]:
    """Return schema and semantic problems for a findings document."""
    if not isinstance(document, dict):
        return [_issue("<document>", "$", "findings document must be a mapping")]
    issues = [
        _issue(
            (error.instance.get("id") if isinstance(error.instance, dict) else None) or document.get("run_id"),
            _format_path(error.path),
            error.message,
        )
        for error in sorted(_validator("findings").iter_errors(document), key=lambda item: list(item.path))
    ]

    findings = document.get("findings")
    if isinstance(findings, list):
        seen: dict[str, int] = {}
        for index, finding in enumerate(findings):
            if not isinstance(finding, dict):
                continue
            identifier = finding.get("id", f"finding[{index}]")
            if isinstance(identifier, str):
                seen[identifier] = seen.get(identifier, 0) + 1
            computed = fingerprint(finding)
            stored = finding.get("fingerprint")
            if stored and stored != computed:
                issues.append(
                    _issue(identifier, f"findings[{index}].fingerprint", "fingerprint does not match the fingerprint fields")
                )
            issues.extend(_history_issues(finding))
            if check_files:
                for evidence_index, evidence in enumerate(_as_list(finding.get("evidence"))):
                    if not isinstance(evidence, dict):
                        continue
                    path = evidence.get("path")
                    if not path:
                        continue
                    resolved = Path(str(path)).expanduser()
                    if not resolved.is_absolute():
                        resolved = Path(base_dir or Path.cwd()).expanduser() / resolved
                    if not resolved.is_file():
                        issues.append(
                            _issue(
                                identifier,
                                f"findings[{index}].evidence[{evidence_index}].path",
                                f"file not found: {resolved}",
                            )
                        )
                        continue
                    digest = sha256_file(resolved)
                    if evidence.get("sha256") and evidence["sha256"] != digest:
                        issues.append(
                            _issue(
                                identifier,
                                f"findings[{index}].evidence[{evidence_index}].sha256",
                                f"hash mismatch: recorded {evidence['sha256']}, file {digest}",
                            )
                        )
        for identifier, count in sorted(seen.items()):
            if count > 1:
                issues.append(_issue(identifier, "$", f"duplicate finding id appears {count} times"))
    return issues


def validate_ledger(
    ledger: Any,
    *,
    source: str = "coverage-ledger",
    base_dir: str | Path | None = None,
    check_files: bool = False,
) -> list[dict[str, str]]:
    """Return schema and consistency problems for a coverage ledger."""
    if not isinstance(ledger, dict):
        return [_issue("<ledger>", "$", "coverage ledger must be a mapping")]
    issues = [
        _issue(
            (error.instance.get("id") if isinstance(error.instance, dict) else None) or ledger.get("run_id"),
            _format_path(error.path),
            error.message,
        )
        for error in sorted(_validator("coverage").iter_errors(ledger), key=lambda item: list(item.path))
    ]
    boundaries = ledger.get("boundaries")
    if not isinstance(boundaries, list):
        return issues
    seen: dict[str, int] = {}
    for index, boundary in enumerate(boundaries):
        if not isinstance(boundary, dict):
            continue
        identifier = str(boundary.get("id", f"boundaries[{index}]"))
        seen[identifier] = seen.get(identifier, 0) + 1
        computed = _boundary_status(boundary)
        if boundary.get("status") in ("covered", "uncovered", "excluded") and boundary.get("status") != computed:
            issues.append(
                _issue(
                    identifier,
                    f"boundaries[{index}].status",
                    f"status {boundary.get('status')!r} contradicts probes; expected {computed!r}",
                )
            )
        probe_ids: set[str] = set()
        for probe_index, probe in enumerate(_as_list(boundary.get("probes"))):
            if not isinstance(probe, dict):
                continue
            probe_id = probe.get("id")
            probe_key = probe_id if isinstance(probe_id, str) else repr(probe_id)
            if probe_key in probe_ids:
                issues.append(
                    _issue(identifier, f"boundaries[{index}].probes[{probe_index}].id", f"duplicate probe id {probe_id!r}")
                )
            probe_ids.add(probe_key)
            if not check_files:
                continue
            for evidence_index, evidence in enumerate(_as_list(probe.get("evidence"))):
                if not isinstance(evidence, dict) or not evidence.get("path"):
                    continue
                resolved = Path(str(evidence["path"])).expanduser()
                if not resolved.is_absolute():
                    resolved = Path(base_dir or Path.cwd()).expanduser() / resolved
                if not resolved.is_file():
                    issues.append(
                        _issue(
                            identifier,
                            f"boundaries[{index}].probes[{probe_index}].evidence[{evidence_index}].path",
                            f"file not found: {resolved}",
                        )
                    )
                elif evidence.get("sha256") and evidence["sha256"] != sha256_file(resolved):
                    issues.append(
                        _issue(
                            identifier,
                            f"boundaries[{index}].probes[{probe_index}].evidence[{evidence_index}].sha256",
                            "hash mismatch",
                        )
                    )
    for identifier, count in sorted(seen.items()):
        if count > 1:
            issues.append(_issue(identifier, "$", f"duplicate boundary id appears {count} times"))
    return issues


def validate_run_metadata(metadata: Any) -> list[dict[str, str]]:
    if not isinstance(metadata, dict):
        return [_issue("<run>", "$", "run metadata must be a mapping")]
    return [
        _issue(
            (error.instance.get("id") if isinstance(error.instance, dict) else None) or metadata.get("run_id"),
            _format_path(error.path),
            error.message,
        )
        for error in sorted(_validator("run").iter_errors(metadata), key=lambda item: list(item.path))
    ]


def _summary(issues: list[dict[str, str]], limit: int = 4) -> str:
    shown = "; ".join(f"{issue['path']}: {issue['message']}" for issue in issues[:limit])
    if len(issues) > limit:
        shown += f" (+{len(issues) - limit} more)"
    return shown


def ensure_valid_document(document: dict[str, Any], *, base_dir: Path | None = None) -> None:
    issues = validate_document(document, base_dir=base_dir)
    if issues:
        raise util.SakError(f"invalid findings: {len(issues)} issue(s): {_summary(issues)}")


# --------------------------------------------------------------------------- #
# Merge, dedupe and status transitions


def _merge_evidence(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        key = (str(record.get("id") or ""), str(record.get("sha256") or record.get("path") or ""))
        if key in seen:
            continue
        seen.add(key)
        merged.append(deepcopy(record))
    return merged


def _merge_findings(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge records sharing one fingerprint, keeping the strongest verdict."""
    ordered = sorted(
        records,
        key=lambda item: (
            -STATUS_PRIORITY.get(str(item.get("status")), 0),
            str(item.get("created_at") or ""),
            str(item.get("id") or ""),
        ),
    )
    winner = deepcopy(ordered[0])
    evidence = _merge_evidence(
        record
        for item in ordered
        for record in _as_list(item.get("evidence"))
    )
    if evidence:
        winner["evidence"] = evidence
    tags: list[str] = []
    for item in ordered:
        for tag in _as_list(item.get("tags")):
            if tag not in tags:
                tags.append(tag)
    if tags:
        winner["tags"] = tags
    for field in ("open_question", "next_action", "reason", "description", "impact", "remediation", "cwe", "notes"):
        if not winner.get(field):
            for item in ordered:
                if item.get(field):
                    winner[field] = item[field]
                    break
    created = sorted(str(item.get("created_at")) for item in ordered if item.get("created_at"))
    updated = sorted(str(item.get("updated_at")) for item in ordered if item.get("updated_at"))
    if created:
        winner["created_at"] = created[0]
    if updated:
        winner["updated_at"] = updated[-1]
    winner["fingerprint"] = fingerprint(winner)
    return winner


def dedupe_document(
    document: dict[str, Any],
    *,
    reason: str = "same asset, entrypoint, root cause, principal and resource",
    now: datetime | str | None = None,
) -> dict[str, Any]:
    """Collapse findings that share a fingerprint and append a dedupe log."""
    deduped = deepcopy(document)
    assign_fingerprints(deduped)
    groups: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for finding in _as_list(deduped.get("findings")):
        if not isinstance(finding, dict):
            continue
        key = finding["fingerprint"]
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(finding)

    collapsed: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for key in order:
        records = groups[key]
        if len(records) == 1:
            findings.append(records[0])
            continue
        winner = _merge_findings(records)
        findings.append(winner)
        retained = False
        removed: list[dict[str, Any]] = []
        for item in records:
            if not retained and item.get("id") == winner.get("id"):
                retained = True
                continue
            removed.append(
                {
                    "id": str(item.get("id")),
                    "title": str(item.get("title") or ""),
                    "status": str(item.get("status") or ""),
                }
            )
        collapsed.append(
            {
                "fingerprint": key,
                "kept": str(winner.get("id")),
                "removed": removed,
                "reason": reason,
            }
        )
    deduped["findings"] = findings
    if collapsed:
        deduped["dedupe"] = _as_list(deduped.get("dedupe")) + collapsed
        deduped["generated_at"] = _now(now)
    deduped["dedupe"] = _as_list(deduped.get("dedupe"))
    assign_fingerprints(deduped)
    return deduped


def merge_document(
    existing: dict[str, Any],
    incoming: dict[str, Any],
    *,
    now: datetime | str | None = None,
) -> dict[str, Any]:
    """Merge an incoming findings document into an existing one."""
    merged = deepcopy(existing)
    merged["findings"] = _as_list(merged.get("findings"))
    merged["dedupe"] = _as_list(merged.get("dedupe"))
    merged["findings"].extend(deepcopy(_as_list(incoming.get("findings"))))
    seen_log = {
        (
            str(group.get("fingerprint")),
            str(group.get("kept")),
            tuple(str(item.get("id")) for item in _as_list(group.get("removed"))),
        )
        for group in merged["dedupe"]
        if isinstance(group, dict)
    }
    for group in _as_list(incoming.get("dedupe")):
        if not isinstance(group, dict):
            continue
        key = (
            str(group.get("fingerprint")),
            str(group.get("kept")),
            tuple(str(item.get("id")) for item in _as_list(group.get("removed"))),
        )
        if key not in seen_log:
            seen_log.add(key)
            merged["dedupe"].append(deepcopy(group))
    if not merged.get("run_id") and incoming.get("run_id"):
        merged["run_id"] = incoming["run_id"]
    merged.setdefault("schema_version", "1")
    merged["generated_at"] = _now(now)
    return dedupe_document(merged, reason="merged on add", now=now)


def set_status(
    document: dict[str, Any],
    finding_id: str,
    new_status: str,
    *,
    actor: str,
    reason: str | None = None,
    open_question: str | None = None,
    next_action: str | None = None,
    evidence: list[dict[str, Any]] | None = None,
    now: datetime | str | None = None,
) -> dict[str, Any]:
    """Apply one status transition with its evidence and open-question rules."""
    if new_status not in STATUSES:
        raise util.SakError(f"unknown status {new_status!r}; expected one of {', '.join(STATUSES)}")
    findings = document.get("findings") or []
    findings = _as_list(findings)
    index = next(
        (position for position, item in enumerate(findings) if isinstance(item, dict) and item.get("id") == finding_id),
        None,
    )
    if index is None:
        raise util.SakError(f"no finding with id {finding_id!r}")
    finding = deepcopy(findings[index])
    current = str(finding.get("status"))
    if new_status != current and new_status not in ALLOWED_TRANSITIONS.get(current, ()):
        allowed = ", ".join(ALLOWED_TRANSITIONS.get(current, ())) or "none"
        raise util.SakError(f"invalid status transition {current} -> {new_status}; allowed from {current}: {allowed}")
    if evidence:
        finding["evidence"] = _merge_evidence(list(finding.get("evidence") or []) + evidence)
    if open_question:
        finding["open_question"] = open_question
    if next_action:
        finding["next_action"] = next_action
    if reason:
        finding["reason"] = reason
    if new_status == "confirmed" and not finding.get("evidence"):
        raise util.SakError("confirmed findings require at least one evidence record")
    if new_status == "needs_validation":
        missing = [field for field in ("open_question", "next_action") if not finding.get(field)]
        if missing:
            raise util.SakError(f"needs_validation requires {', '.join(missing)}")
    if new_status == "rejected" and not finding.get("reason"):
        raise util.SakError("rejected findings require a reason")
    stamp = _now(now)
    if new_status != current:
        history = finding.get("status_history")
        if history is not None and not isinstance(history, list):
            raise util.SakError(f"{finding_id}: status_history must be a list")
        transition: dict[str, Any] = {"from": current, "to": new_status, "at": stamp, "actor": actor}
        if reason:
            transition["reason"] = reason
        finding.setdefault("status_history", []).append(transition)
    finding["status"] = new_status
    finding["updated_at"] = stamp
    finding["fingerprint"] = fingerprint(finding)
    findings[index] = finding
    document["findings"] = findings
    document["generated_at"] = stamp
    return finding


# --------------------------------------------------------------------------- #
# Coverage ledger


def _probe_executed(probe: dict[str, Any]) -> bool:
    return bool(probe.get("executed"))


def _boundary_status(boundary: dict[str, Any]) -> str:
    if any(
        _probe_executed(probe)
        for probe in _as_list(boundary.get("probes"))
        if isinstance(probe, dict)
    ):
        return "covered"
    if boundary.get("status") == "excluded":
        return "excluded"
    return "uncovered"


def refresh_ledger(ledger: dict[str, Any], *, now: datetime | str | None = None) -> dict[str, Any]:
    """Recompute every boundary status from its probes."""
    refreshed = deepcopy(ledger)
    for boundary in _as_list(refreshed.get("boundaries")):
        if isinstance(boundary, dict):
            boundary["status"] = _boundary_status(boundary)
    refreshed["generated_at"] = _now(now)
    return refreshed


def _merge_boundary(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(existing)
    for field in ("name", "description", "gap", "notes"):
        if incoming.get(field) is not None:
            merged[field] = deepcopy(incoming[field])
    probe_map: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for probe in _as_list(existing.get("probes")) + _as_list(incoming.get("probes")):
        if not isinstance(probe, dict):
            continue
        identifier = str(probe.get("id") or "")
        if identifier not in probe_map:
            probe_map[identifier] = deepcopy(probe)
            order.append(identifier)
            continue
        current = probe_map[identifier]
        for field, value in probe.items():
            if field == "evidence":
                current["evidence"] = _merge_evidence(
                    _as_list(current.get("evidence")) + _as_list(value)
                )
            elif field == "executed":
                current["executed"] = bool(current.get("executed")) or bool(value)
            elif value is not None:
                current[field] = deepcopy(value)
    merged["probes"] = [probe_map[key] for key in order]
    statuses = {str(existing.get("status")), str(incoming.get("status"))}
    if any(_probe_executed(probe) for probe in merged["probes"]):
        merged["status"] = "covered"
    elif "excluded" in statuses:
        merged["status"] = "excluded"
    else:
        merged["status"] = "uncovered"
    return merged


def merge_ledger(
    existing: dict[str, Any] | None,
    incoming: dict[str, Any],
    *,
    now: datetime | str | None = None,
) -> dict[str, Any]:
    """Merge coverage updates by boundary and probe id.

    Rules: boundaries match on ``id``; probes match on ``id``; an executed
    probe is never downgraded by a later planned record; evidence is unioned;
    an exclusion survives a planned-only update; any executed probe means the
    boundary is covered.  Status is always recomputed from probes.
    """
    merged = deepcopy(existing) if existing else empty_ledger(str(incoming.get("run_id") or "run"))
    merged["boundaries"] = _as_list(merged.get("boundaries"))
    by_id = {
        str(boundary.get("id")): position
        for position, boundary in enumerate(merged["boundaries"])
        if isinstance(boundary, dict)
    }
    for boundary in _as_list(incoming.get("boundaries")):
        if not isinstance(boundary, dict):
            continue
        identifier = str(boundary.get("id") or "")
        if identifier in by_id:
            position = by_id[identifier]
            merged["boundaries"][position] = _merge_boundary(merged["boundaries"][position], boundary)
        else:
            by_id[identifier] = len(merged["boundaries"])
            merged["boundaries"].append(deepcopy(boundary))
    if not merged.get("run_id"):
        merged["run_id"] = incoming.get("run_id")
    merged.setdefault("schema_version", "1")
    return refresh_ledger(merged, now=now)


def ledger_gaps(ledger: dict[str, Any]) -> list[dict[str, str]]:
    """Return every boundary that is not covered, with its recorded reason."""
    gaps: list[dict[str, str]] = []
    for boundary in _as_list(ledger.get("boundaries")):
        if not isinstance(boundary, dict):
            continue
        status = _boundary_status(boundary)
        if status == "covered":
            continue
        reason = str(boundary.get("gap") or "").strip()
        if not reason:
            reason = "excluded from scope" if status == "excluded" else "planned but no probe executed"
        gaps.append(
            {
                "id": str(boundary.get("id") or ""),
                "name": str(boundary.get("name") or ""),
                "status": status,
                "reason": reason,
            }
        )
    return gaps


def coverage_summary(ledger: dict[str, Any]) -> dict[str, Any]:
    boundaries = [item for item in _as_list(ledger.get("boundaries")) if isinstance(item, dict)]
    covered = sum(1 for boundary in boundaries if _boundary_status(boundary) == "covered")
    excluded = sum(1 for boundary in boundaries if _boundary_status(boundary) == "excluded")
    total = len(boundaries)
    return {
        "boundaries": total,
        "covered": covered,
        "excluded": excluded,
        "uncovered": total - covered - excluded,
        "gaps": len(ledger_gaps(ledger)),
        "ratio": (covered / total) if total else None,
    }


# --------------------------------------------------------------------------- #
# Adapter candidate import

IMPORT_DEFAULT_ASSET = "unknown-target"
IMPORT_DEFAULT_PRINCIPAL = "unknown"
IMPORT_DEFAULT_RESOURCE = "reported target"
IMPORT_SOURCE_FIELDS = ("tool", "prompt", "adapter", "engine", "model")
IMPORT_SEVERITY_ALIASES = {
    "moderate": "medium",
    "med": "medium",
    "informational": "info",
    "information": "info",
    "unknown": "info",
    "none": "info",
}
_HOST_PORT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*:\d+$")
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@]+@")


def _sanitize_import_text(value: Any) -> str:
    """Mask secrets and URL credentials in one candidate-derived string."""
    return _URL_USERINFO.sub(r"\1***@", mask_text(_collapse(value)))


def _candidate_info(candidate: dict[str, Any]) -> dict[str, Any]:
    info = candidate.get("info")
    return info if isinstance(info, dict) else {}


def _candidate_text(candidate: dict[str, Any], *names: str) -> str:
    """Read the first non-empty scalar under the candidate or its info block."""
    info = _candidate_info(candidate)
    for name in names:
        for container in (candidate, info):
            value = container.get(name)
            if isinstance(value, (str, int, float)) and not isinstance(value, bool):
                text = _collapse(value)
                if text:
                    return text
    return ""


def _import_severity(value: Any) -> tuple[str, str | None]:
    text = _collapse(value).lower()
    if text in SEVERITIES:
        return text, None
    if not text:
        return "info", None
    mapped = IMPORT_SEVERITY_ALIASES.get(text, "info")
    return mapped, f"severity {text!r} mapped to {mapped!r}"


def _import_target(candidate: dict[str, Any]) -> tuple[str, str, bool]:
    """Split a candidate target into a schema asset and entrypoint."""
    target = _candidate_text(candidate, "target", "matched-at", "matched_at", "url", "host")
    fallback_entry = _candidate_text(candidate, "entrypoint", "path") or "/"
    if not target:
        return IMPORT_DEFAULT_ASSET, fallback_entry, False
    try:
        parsed = urlsplit(target)
    except ValueError:
        return _sanitize_import_text(target), fallback_entry, True
    if parsed.scheme and parsed.netloc:
        try:
            port = f":{parsed.port}" if parsed.port else ""
        except ValueError:
            return _sanitize_import_text(target), fallback_entry, True
        host = parsed.hostname or ""
        asset = f"{parsed.scheme.lower()}://{host}{port}" if host else _sanitize_import_text(target)
        entrypoint = parsed.path or "/"
        if parsed.query:
            entrypoint = f"{entrypoint}?{parsed.query}"
        return _sanitize_import_text(asset), _sanitize_import_text(entrypoint), True
    if _HOST_PORT.match(target):
        return _sanitize_import_text(target.lower()), fallback_entry, True
    return _sanitize_import_text(target), fallback_entry, True


def _import_slug(value: Any, fallback: str) -> str:
    slug = re.sub(r"[^a-z0-9._-]+", "-", _collapse(value).lower()).strip("-._")
    return slug or fallback


def _import_root_cause(candidate: dict[str, Any], title: str) -> str:
    value = _candidate_text(candidate, "root_cause", "template-id", "template", "check", "type", "category")
    if not value:
        evidence = candidate.get("evidence")
        if isinstance(evidence, dict):
            value = _candidate_text(evidence, "template", "check", "rule", "type")
    return _import_slug(value or title, "candidate-reported")


def _import_source(candidate: dict[str, Any]) -> dict[str, str]:
    """Map a string or object source onto the schema's source object."""
    record: dict[str, str] = {}
    raw = candidate.get("source")
    if isinstance(raw, str):
        text = _sanitize_import_text(raw)
        if text:
            record["tool"] = text
    elif isinstance(raw, dict):
        for key in IMPORT_SOURCE_FIELDS:
            value = raw.get(key)
            if isinstance(value, str) and value.strip():
                record[key] = _sanitize_import_text(value)
    for key in IMPORT_SOURCE_FIELDS:
        if key in record:
            continue
        value = candidate.get(key)
        if isinstance(value, str) and value.strip():
            record[key] = _sanitize_import_text(value)
    return record or {"adapter": "findings-import"}


def _sanitize_import_value(value: Any, *, depth: int = 0) -> Any:
    """Recursively mask a candidate record before it is written as evidence."""
    if depth > 20:
        return "***"
    if isinstance(value, str):
        return _sanitize_import_text(value)
    if isinstance(value, dict):
        return {str(key): _sanitize_import_value(item, depth=depth + 1) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize_import_value(item, depth=depth + 1) for item in value]
    return value


def _import_finding_id(candidate: dict[str, Any], digest: str, used_ids: set[str]) -> str:
    """Keep a valid candidate F-id, otherwise derive a stable id from the digest."""
    raw = candidate.get("id")
    base = ""
    if isinstance(raw, str) and raw.strip():
        text = raw.strip()
        if re.fullmatch(r"F-[A-Za-z0-9][A-Za-z0-9._-]*", text):
            base = text
        else:
            slug = re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-._")
            if slug:
                base = f"F-{slug[:48]}"
    if not base:
        base = f"F-{digest[:16]}"
    if base in used_ids:
        base = f"{base}-{digest[:8]}"
    candidate_id = base
    counter = 2
    while candidate_id in used_ids:
        candidate_id = f"{base}-{counter}"
        counter += 1
    return candidate_id


def _write_candidate_evidence(
    run_dir: Path,
    finding_id: str,
    candidate: dict[str, Any],
    source_label: str,
    timestamp: str,
) -> str:
    """Write a sanitized candidate JSON under the run directory; return its relative path."""
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", finding_id).strip("-._")[:96] or "candidate"
    evidence_dir = run_dir / "evidence"
    util.ensure_directory(evidence_dir)
    path = evidence_dir / f"{name}-candidate.json"
    root = run_dir.resolve()
    resolved = path.resolve()
    if root != resolved.parent and root not in resolved.parents:
        raise util.SakError(f"refusing to write evidence outside the run directory: {resolved}")
    payload = {
        "source": source_label,
        "imported_at": timestamp,
        "candidate": _sanitize_import_value(candidate),
    }
    path.write_text(util.dump_json(payload), encoding="utf-8")
    return path.relative_to(run_dir).as_posix()


def _candidate_finding(
    candidate: dict[str, Any], index: int, *, source_label: str
) -> tuple[dict[str, Any], list[str]]:
    """Map one adapter candidate to a needs_validation finding draft."""
    fallback_title = f"Imported candidate {index}"
    title = _sanitize_import_text(
        _candidate_text(candidate, "title", "name", "template-id", "template", "check")
    ) or fallback_title
    severity, severity_warning = _import_severity(_candidate_text(candidate, "severity"))
    asset, entrypoint, had_target = _import_target(candidate)
    root_cause = _import_root_cause(candidate, title)
    principal = (
        _sanitize_import_text(_candidate_text(candidate, "principal", "user", "account"))
        or IMPORT_DEFAULT_PRINCIPAL
    )
    resource = (
        _sanitize_import_text(_candidate_text(candidate, "resource", "endpoint"))
        or IMPORT_DEFAULT_RESOURCE
    )
    source = _import_source(candidate)
    stamp = _now()
    finding: dict[str, Any] = {
        "title": title,
        "status": "needs_validation",
        "severity": severity,
        "asset": asset or IMPORT_DEFAULT_ASSET,
        "entrypoint": entrypoint or "/",
        "root_cause": root_cause,
        "principal": principal,
        "resource": resource,
        "source": source,
        "open_question": (
            f"Is the reported {root_cause} at {entrypoint} on {asset} reproducible under authorization?"
        ),
        "next_action": (
            f"Replay the {source.get('tool') or source.get('adapter') or 'adapter'} report for "
            f"{asset}{entrypoint}, capture sanitized request and response evidence, then verify "
            "before changing the status."
        ),
        "created_at": stamp,
        "updated_at": stamp,
    }
    description = _sanitize_import_text(
        _candidate_text(candidate, "description", "summary", "detail", "details")
    )
    if description:
        finding["description"] = description
    warnings: list[str] = []
    if not had_target:
        warnings.append(
            f"candidate {index}: missing target; recorded asset {IMPORT_DEFAULT_ASSET!r}"
        )
    if severity_warning:
        warnings.append(f"candidate {index}: {severity_warning}")
    return finding, warnings


def _load_candidates(source: str) -> tuple[list[Any], str]:
    """Read a raw adapter candidate list or a document with a findings array."""
    if str(source).strip() in ("-", "stdin"):
        label = "stdin"
        try:
            data = json.loads(sys.stdin.read())
        except json.JSONDecodeError as exc:
            raise util.SakError(f"invalid JSON in stdin: {exc}") from exc
    else:
        path = Path(source).expanduser()
        if path.is_dir():
            raise util.SakError(f"candidate source must be a file: {path}")
        if not path.is_file():
            raise util.SakError(f"candidate source not found: {path}")
        label = path.name
        if path.suffix.lower() in (".yaml", ".yml"):
            data = util.load_yaml(path)
        else:
            try:
                text = path.read_text(encoding="utf-8")
            except OSError as exc:
                raise util.SakError(f"cannot read {path}: {exc}") from exc
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                raise util.SakError(f"invalid JSON in {path}: {exc}") from exc

    if isinstance(data, list):
        return data, label
    if isinstance(data, dict):
        if "findings" in data:
            findings = data.get("findings")
            if not isinstance(findings, list):
                raise util.SakError(f"candidate document 'findings' must be an array in {label}")
            return findings, label
        return [data], label
    raise util.SakError(f"candidate source {label} must contain a JSON array or object")


# --------------------------------------------------------------------------- #
# CLI


def _destination(args: argparse.Namespace, default: str = DEFAULT_FINDINGS) -> Path:
    run_dir = getattr(args, "run_dir", None)
    if run_dir:
        return Path(run_dir).expanduser() / default
    return Path(getattr(args, "file", None) or default).expanduser()


def _run_id_for(path: Path) -> str:
    parent = path.parent.name
    return parent if parent and parent not in (".", "") else "ad-hoc"


def _input_document(source: str, *, base_dir: Path) -> tuple[dict[str, Any], int]:
    text, path = _read_text(source)
    if path is not None and path.suffix.lower() in (".yaml", ".yml"):
        data = util.load_yaml(path)
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            label = str(path) if path is not None else "stdin"
            raise util.SakError(f"invalid JSON in {label}: {exc}") from exc
    if not isinstance(data, dict):
        raise util.SakError("findings input must be a JSON object or findings document")
    if isinstance(data.get("findings"), list):
        document = data
        document.setdefault("schema_version", "1")
        document.setdefault("run_id", _run_id_for(base_dir / DEFAULT_FINDINGS))
        document.setdefault("generated_at", _now())
        document.setdefault("dedupe", [])
    else:
        document = empty_document(_run_id_for(base_dir / DEFAULT_FINDINGS))
        document["findings"] = [data]
    for finding in document["findings"]:
        if not isinstance(finding, dict):
            raise util.SakError("each finding must be a JSON object")
        finding.setdefault("created_at", _now())
        finding.setdefault("updated_at", _now())
        _enrich_evidence(finding, base_dir=base_dir, producer="sak findings add")
        finding["fingerprint"] = fingerprint(finding)
    return document, len(document["findings"])


def _remove_duplicates_from_findings(document: dict[str, Any]) -> int:
    return sum(
        len(_as_list(group.get("removed")))
        for group in _as_list(document.get("dedupe"))
        if isinstance(group, dict)
    )


def _write_document(path: Path, document: dict[str, Any]) -> None:
    util.ensure_directory(path.parent)
    path.write_text(util.dump_json(document), encoding="utf-8")


def _finding_rows(findings: list[dict[str, Any]]) -> list[list[Any]]:
    return [
        [
            finding.get("id"),
            finding.get("status"),
            finding.get("severity"),
            finding.get("asset"),
            finding.get("title"),
        ]
        for finding in findings
    ]


def handle_validate(args: argparse.Namespace) -> int:
    path = Path(args.file or DEFAULT_FINDINGS).expanduser()
    document, resolved = load_document(path)
    base_dir = (resolved or path).parent
    issues = validate_document(document, source=str(path), base_dir=base_dir, check_files=not args.no_files)
    report = {
        "ok": not issues,
        "source": str(resolved or path),
        "run_id": document.get("run_id"),
        "findings": len(document.get("findings") or []),
        "errors": issues,
    }
    if args.json:
        util.emit_json(report)
    elif issues:
        for issue in issues:
            print(f"{issue['id']}: {issue['path']}: {issue['message']}")
        print(f"FAIL: {len(issues)} issue(s) in {report['source']}")
    else:
        print(f"OK: {report['findings']} findings in {report['source']}")
    return 0 if not issues else 1


def handle_list(args: argparse.Namespace) -> int:
    path = Path(args.file or DEFAULT_FINDINGS).expanduser()
    document, resolved = load_document(path)
    issues = validate_document(
        document,
        source=str(path),
        base_dir=(resolved or path).parent,
        check_files=False,
    )
    if issues:
        raise util.SakError(f"invalid findings: {_summary(issues)}")
    findings = [item for item in _as_list(document.get("findings")) if isinstance(item, dict)]
    if args.status:
        findings = [item for item in findings if item.get("status") == args.status]
    if args.severity:
        findings = [item for item in findings if item.get("severity") == args.severity]
    findings.sort(key=lambda item: (-STATUS_PRIORITY.get(str(item.get("status")), 0), str(item.get("id"))))
    if args.json:
        util.emit_json(findings)
    elif not findings:
        print("no findings matched")
    else:
        print(mask_text(util.table(_finding_rows(findings), ["ID", "STATUS", "SEVERITY", "ASSET", "TITLE"])))
    return 0


def handle_add(args: argparse.Namespace) -> int:
    destination = _destination(args)
    base_dir = destination.parent
    incoming, added = _input_document(args.source, base_dir=base_dir)
    if destination.is_file():
        existing, _ = load_document(destination)
        issues = validate_document(existing, source=str(destination), check_files=False)
        if issues:
            raise util.SakError(f"invalid findings {destination}: {_summary(issues)}")
        document = merge_document(existing, incoming)
    else:
        document = dedupe_document(incoming)
    ensure_valid_document(document, base_dir=base_dir)
    _write_document(destination, document)
    removed = _remove_duplicates_from_findings(document)
    summary = {
        "ok": True,
        "written": str(destination),
        "added": added,
        "total": len(document.get("findings") or []),
        "duplicates_removed": removed,
        "run_id": document.get("run_id"),
    }
    if args.json:
        util.emit_json(summary)
    else:
        print(
            f"added {added} finding(s) to {destination}: "
            f"{summary['total']} total, {removed} duplicate(s) collapsed"
        )
    return 0


def handle_import(args: argparse.Namespace) -> int:
    candidates, source_label = _load_candidates(args.source)
    for index, candidate in enumerate(candidates, start=1):
        if not isinstance(candidate, dict):
            raise util.SakError(f"candidate {index} must be a JSON object")
    run_dir = Path(args.run_dir or ".").expanduser()
    if run_dir.exists() and not run_dir.is_dir():
        raise util.SakError(f"run path is not a directory: {run_dir}")
    util.ensure_directory(run_dir)
    destination = run_dir / DEFAULT_FINDINGS

    if destination.is_file():
        existing, _ = load_document(destination)
        issues = validate_document(
            existing, source=str(destination), base_dir=run_dir, check_files=False
        )
        if issues:
            raise util.SakError(f"invalid findings {destination}: {_summary(issues)}")
        document = deepcopy(existing)
    else:
        document = empty_document(_run_id_for(destination))
    document.setdefault("schema_version", "1")
    document.setdefault("run_id", _run_id_for(destination))
    document.setdefault("dedupe", [])
    document["findings"] = _as_list(document.get("findings"))

    findings = document["findings"]
    seen = {fingerprint(item) for item in findings if isinstance(item, dict)}
    used_ids = {
        str(item.get("id")) for item in findings if isinstance(item, dict) and item.get("id")
    }
    imported_ids: list[str] = []
    warnings: list[str] = []
    skipped = 0
    stamp = _now()

    for index, candidate in enumerate(candidates, start=1):
        finding, candidate_warnings = _candidate_finding(
            candidate, index, source_label=source_label
        )
        warnings.extend(candidate_warnings)
        digest = fingerprint(finding)
        if digest in seen:
            skipped += 1
            continue
        finding_id = _import_finding_id(candidate, digest, used_ids)
        evidence_path = _write_candidate_evidence(
            run_dir, finding_id, candidate, source_label, stamp
        )
        evidence = evidence_from_file(
            evidence_path,
            kind="other",
            producer="sak findings import",
            base_dir=run_dir,
            timestamp=stamp,
            description=f"Candidate record imported from {source_label}",
        )
        finding["id"] = finding_id
        finding["evidence"] = [evidence]
        finding["fingerprint"] = fingerprint(finding)
        findings.append(finding)
        seen.add(digest)
        used_ids.add(finding_id)
        imported_ids.append(finding_id)

    document["generated_at"] = stamp
    ensure_valid_document(document, base_dir=run_dir)
    _write_document(destination, document)

    summary = {
        "ok": True,
        "source": source_label,
        "written": str(destination),
        "run_id": document.get("run_id"),
        "imported": len(imported_ids),
        "skipped_duplicates": skipped,
        "total": len(findings),
        "ids": imported_ids,
        "warnings": warnings,
    }
    if args.json:
        util.emit_json(summary)
    else:
        print(
            f"imported {len(imported_ids)} candidate(s) into {destination}: "
            f"{skipped} duplicate(s) skipped, {len(findings)} total"
        )
        for warning in warnings:
            print(f"warning: {warning}")
    return 0


def handle_dedupe(args: argparse.Namespace) -> int:
    path = Path(args.file or DEFAULT_FINDINGS).expanduser()
    document, resolved = load_document(path)
    issues = validate_document(document, source=str(path), base_dir=(resolved or path).parent, check_files=False)
    if issues:
        raise util.SakError(f"invalid findings: {_summary(issues)}")
    before = len(document.get("findings") or [])
    deduped = dedupe_document(document)
    removed = _remove_duplicates_from_findings(deduped)
    if args.write:
        _write_document(path, deduped)
    if args.json:
        util.emit_json(deduped)
    else:
        after = len(deduped.get("findings") or [])
        print(f"dedupe: {before} -> {after} finding(s); {removed} duplicate(s) removed")
        for group in _as_list(deduped.get("dedupe")):
            removed_ids = ", ".join(item.get("id", "?") for item in _as_list(group.get("removed")))
            print(f"  {group.get('fingerprint', '')[:12]}  keep {group.get('kept')}  drop {removed_ids}")
        if args.write:
            print(f"wrote {path}")
    return 0


def handle_status(args: argparse.Namespace) -> int:
    destination = _destination(args)
    document, resolved = load_document(destination)
    base_dir = (resolved or destination).parent
    issues = validate_document(document, source=str(destination), check_files=False)
    if issues:
        raise util.SakError(f"invalid findings {destination}: {_summary(issues)}")
    evidence = [
        evidence_from_file(path, kind=args.evidence_kind, producer=args.actor, base_dir=base_dir)
        for path in (args.evidence or [])
    ]
    finding = set_status(
        document,
        args.id,
        args.new_status,
        actor=args.actor,
        reason=args.reason,
        open_question=args.open_question,
        next_action=args.next_action,
        evidence=evidence,
    )
    ensure_valid_document(document, base_dir=base_dir)
    _write_document(destination, document)
    if args.json:
        util.emit_json({"ok": True, "written": str(destination), "finding": finding})
    else:
        print(f"{finding['id']}: {finding['status']} (fingerprint {finding['fingerprint'][:12]})")
        print(f"wrote {destination}")
    return 0


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("findings", help="record, validate, dedupe and triage findings")
    commands = parser.add_subparsers(dest="findings_command", required=True)

    validate = commands.add_parser("validate", help="validate findings and evidence hashes")
    validate.add_argument("file", nargs="?", help="findings document (default: findings.json)")
    validate.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    validate.add_argument("--no-files", action="store_true", help="do not check evidence files on disk")
    validate.set_defaults(func=handle_validate)

    listing = commands.add_parser("list", help="list findings")
    listing.add_argument("file", nargs="?", help="findings document (default: findings.json)")
    listing.add_argument("--status", choices=STATUSES)
    listing.add_argument("--severity", choices=SEVERITIES)
    listing.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    listing.set_defaults(func=handle_list)

    add = commands.add_parser("add", help="add findings from a file or stdin")
    add.add_argument("source", nargs="?", default="-", help="finding or findings document, or - for stdin")
    add.add_argument("--file", help="destination findings document (default: findings.json)")
    add.add_argument("--run-dir", help="write to <run-dir>/findings.json")
    add.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    add.set_defaults(func=handle_add)

    importer = commands.add_parser(
        "import", help="import adapter candidate findings as needs_validation records"
    )
    importer.add_argument(
        "source",
        nargs="?",
        default="-",
        help="raw candidate list, document with findings, or - for stdin",
    )
    importer.add_argument(
        "--run-dir",
        default=".",
        help="run directory for findings.json and sanitized evidence (default: current directory)",
    )
    importer.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    importer.set_defaults(func=handle_import)

    dedupe = commands.add_parser("dedupe", help="collapse records that share a fingerprint")
    dedupe.add_argument("file", nargs="?", help="findings document (default: findings.json)")
    dedupe.add_argument("--write", action="store_true", help="write the deduped document back")
    dedupe.add_argument("--json", action="store_true", help="emit the deduped document")
    dedupe.set_defaults(func=handle_dedupe)

    status = commands.add_parser("status", help="apply a validated status transition")
    status.add_argument("id", help="finding id")
    status.add_argument("new_status", choices=STATUSES)
    status.add_argument("--file", help="findings document (default: findings.json)")
    status.add_argument("--run-dir", help="use <run-dir>/findings.json")
    status.add_argument("--actor", default="operator", help="who made the decision")
    status.add_argument("--reason")
    status.add_argument("--open-question", dest="open_question")
    status.add_argument("--next-action", dest="next_action")
    status.add_argument("--evidence", action="append", help="evidence file path (repeatable)")
    status.add_argument(
        "--evidence-kind",
        default="observed",
        choices=("request", "response", "command", "log", "source", "observed", "screenshot", "other"),
    )
    status.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    status.set_defaults(func=handle_status)

    parser.set_defaults(func=handle_list)
