"""Render human reports from a run directory.

``sak report RUN_DIR`` reads the run's findings, coverage ledger and metadata
and writes ``REPORT.md``, ``FINDINGS-DETAIL.md`` and ``NEEDS-VALIDATION.md``.
It never executes a tool and never prints an unmasked secret: every rendered
string passes through :func:`sak.findings.mask_text`.
"""

from __future__ import annotations

import argparse
import json
import re
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import findings as findings_module
from . import util

REPORT_FILES = ("REPORT.md", "FINDINGS-DETAIL.md", "NEEDS-VALIDATION.md")
METADATA_FILES = ("run-metadata.json", "state.json")
SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


@dataclass
class RunData:
    path: Path
    findings: dict[str, Any]
    ledger: dict[str, Any]
    metadata: dict[str, Any]
    warnings: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    integrity: dict[str, str] = field(default_factory=dict)

    @property
    def run_id(self) -> str:
        return str(self.metadata.get("run_id") or self.findings.get("run_id") or self.path.name)


def _now(now: datetime | None = None) -> str:
    moment = now or datetime.now(timezone.utc)
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _read_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise util.SakError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise util.SakError(f"invalid JSON in {path}: {exc}") from exc


def _issues_text(issues: Iterable[dict[str, str]], limit: int = 5) -> str:
    items = list(issues)
    shown = "; ".join(f"{issue['path']}: {issue['message']}" for issue in items[:limit])
    if len(items) > limit:
        shown += f" (+{len(items) - limit} more)"
    return shown


def _resolve_evidence_path(run_dir: Path, path: str) -> Path:
    candidate = Path(path).expanduser()
    return candidate if candidate.is_absolute() else run_dir / candidate


def _collect_evidence(data: RunData) -> list[dict[str, Any]]:
    """Index evidence from findings and coverage probes, with integrity state."""
    indexed: dict[str, dict[str, Any]] = {}
    candidates: list[tuple[dict[str, Any], str]] = []
    for finding in _as_list(data.findings.get("findings")):
        if not isinstance(finding, dict):
            continue
        for evidence in _as_list(finding.get("evidence")):
            if isinstance(evidence, dict):
                candidates.append((evidence, str(finding.get("id") or "")))
    for boundary in _as_list(data.ledger.get("boundaries")):
        if not isinstance(boundary, dict):
            continue
        for probe in _as_list(boundary.get("probes")):
            if not isinstance(probe, dict):
                continue
            for evidence in _as_list(probe.get("evidence")):
                if isinstance(evidence, dict):
                    candidates.append((evidence, str(boundary.get("id") or "")))
    for evidence, owner in candidates:
        identifier = str(evidence.get("id") or f"{owner}-evidence")
        if identifier in indexed:
            if owner not in indexed[identifier]["owners"]:
                indexed[identifier]["owners"].append(owner)
            continue
        record = deepcopy(evidence)
        record["owners"] = [owner]
        path = _resolve_evidence_path(data.path, str(evidence.get("path") or ""))
        if not path.is_file():
            record["integrity"] = "missing"
        elif evidence.get("sha256") and findings_module.sha256_file(path) != evidence["sha256"]:
            record["integrity"] = "hash mismatch"
        else:
            record["integrity"] = "verified"
        indexed[identifier] = record
    return [indexed[key] for key in sorted(indexed)]


def load_run(run_dir: str | Path) -> RunData:
    path = Path(run_dir).expanduser()
    if not path.exists():
        raise util.SakError(f"run directory does not exist: {path}")
    if not path.is_dir():
        raise util.SakError(f"run path is not a directory: {path}")
    warnings: list[str] = []

    metadata: dict[str, Any] = {}
    metadata_path = next((path / name for name in METADATA_FILES if (path / name).is_file()), None)
    if metadata_path is None:
        warnings.append("run metadata is missing; the report uses the directory name as the run id")
    else:
        raw_metadata = _read_json(metadata_path)
        if not isinstance(raw_metadata, dict):
            raise util.SakError(f"run metadata {metadata_path} must be a JSON object")
        if metadata_path.name == "state.json":
            # state.json is a best-effort alias owned by the run state; ignore
            # fields this report does not consume instead of failing the render.
            allowed = {
                "schema_version",
                "run_id",
                "started_at",
                "ended_at",
                "target",
                "suite",
                "plan",
                "revision",
                "operator",
                "budget",
                "usage",
                "notes",
            }
            metadata = {key: value for key, value in raw_metadata.items() if key in allowed}
        else:
            metadata = raw_metadata
            issues = findings_module.validate_run_metadata(metadata)
            if issues:
                raise util.SakError(f"invalid run metadata {metadata_path}: {_issues_text(issues)}")

    run_id = str(metadata.get("run_id") or path.name)
    findings_path = path / "findings.json"
    if findings_path.is_file():
        document = _read_json(findings_path)
    else:
        warnings.append("findings.json is missing; the report renders no findings")
        document = findings_module.empty_document(run_id)
    issues = findings_module.validate_document(document, source=str(findings_path), check_files=False)
    if issues:
        raise util.SakError(f"invalid findings {findings_path}: {_issues_text(issues)}")
    if document.get("run_id") and document.get("run_id") != run_id:
        warnings.append(
            f"findings run_id {document.get('run_id')!r} differs from metadata run_id {run_id!r}"
        )

    ledger_path = path / "coverage-ledger.json"
    if ledger_path.is_file():
        ledger = _read_json(ledger_path)
    else:
        warnings.append("coverage-ledger.json is missing; the report cannot state boundary coverage")
        ledger = findings_module.empty_ledger(run_id)
    issues = findings_module.validate_ledger(ledger, source=str(ledger_path), check_files=False)
    if issues:
        raise util.SakError(f"invalid coverage ledger {ledger_path}: {_issues_text(issues)}")

    data = RunData(path=path, findings=document, ledger=ledger, metadata=metadata, warnings=warnings)
    data.evidence = _collect_evidence(data)
    data.integrity = {
        str(item.get("id")): str(item.get("integrity")) for item in data.evidence
    }
    duplicate_groups = 0
    seen: set[str] = set()
    for finding in _as_list(document.get("findings")):
        if not isinstance(finding, dict):
            continue
        key = findings_module.fingerprint(finding)
        if key in seen:
            duplicate_groups += 1
        seen.add(key)
    if duplicate_groups:
        data.warnings.append(
            f"{duplicate_groups} record(s) share a fingerprint; run 'sak findings dedupe --write' before trusting counts"
        )
    return data


def _counts(records: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = {status: 0 for status in findings_module.STATUSES}
    for record in records:
        status = str(record.get("status"))
        if status in counts:
            counts[status] += 1
    counts["total"] = sum(counts.values())
    return counts


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _record_evidence_state(record: dict[str, Any], integrity: dict[str, str]) -> str:
    evidence = [item for item in _as_list(record.get("evidence")) if isinstance(item, dict)]
    if not evidence:
        return "none"
    verified = all(integrity.get(str(item.get("id"))) == "verified" for item in evidence)
    return "verified" if verified else "invalid"


def _valid_confirmed(data: RunData) -> list[dict[str, Any]]:
    return [
        record
        for record in _status_records(data, "confirmed")
        if _record_evidence_state(record, data.integrity) == "verified"
    ]


def _invalid_confirmed(data: RunData) -> list[dict[str, Any]]:
    return [
        record
        for record in _status_records(data, "confirmed")
        if _record_evidence_state(record, data.integrity) != "verified"
    ]


def _rendered_counts(data: RunData) -> dict[str, int]:
    raw = _counts(_as_list(data.findings.get("findings")))
    valid = _valid_confirmed(data)
    invalid = _invalid_confirmed(data)
    return {
        "total": raw["total"],
        "confirmed": len(valid),
        "needs_validation": raw["needs_validation"],
        "rejected": raw["rejected"],
        "excluded_confirmed": len(invalid),
    }


def _probe_verified(data: RunData, probe: dict[str, Any]) -> bool:
    evidenced = [
        item for item in _as_list(probe.get("evidence")) if isinstance(item, dict)
    ]
    if not evidenced:
        return False
    return all(data.integrity.get(str(item.get("id"))) == "verified" for item in evidenced)


def _coverage_view(data: RunData) -> dict[str, Any]:
    """Effective coverage: executed probes with at least one verified evidence record."""
    boundaries = [item for item in _as_list(data.ledger.get("boundaries")) if isinstance(item, dict)]
    rows: list[tuple[Any, ...]] = []
    gaps: list[dict[str, str]] = []
    counts = {"covered": 0, "unverified": 0, "excluded": 0, "uncovered": 0}
    for boundary in boundaries:
        probes = [item for item in _as_list(boundary.get("probes")) if isinstance(item, dict)]
        executed = [probe for probe in probes if probe.get("executed")]
        verified = [probe for probe in executed if _probe_verified(data, probe)]
        stored = boundary.get("status")
        if verified:
            status = "covered"
        elif executed:
            status = "unverified"
        elif stored == "excluded":
            status = "excluded"
        else:
            status = "uncovered"
        counts[status] += 1
        links = ", ".join(
            _link(str(evidence.get("path")), str(evidence.get("id")))
            for probe in executed
            for evidence in _as_list(probe.get("evidence"))
            if isinstance(evidence, dict) and evidence.get("path")
        )
        rows.append(
            (
                boundary.get("id"),
                boundary.get("name"),
                status,
                f"{len(executed)}/{len(probes)}",
                links or "-",
            )
        )
        if status == "covered":
            continue
        reason = str(boundary.get("gap") or "").strip()
        if status == "unverified":
            reason = "executed probe evidence is missing or failed its hash check"
        elif not reason:
            reason = "excluded from scope" if status == "excluded" else "planned but no probe executed"
        gaps.append(
            {
                "id": str(boundary.get("id") or ""),
                "name": str(boundary.get("name") or ""),
                "status": status,
                "reason": reason,
            }
        )
    total = len(boundaries)
    return {
        "boundaries": total,
        "covered": counts["covered"],
        "unverified": counts["unverified"],
        "excluded": counts["excluded"],
        "uncovered": counts["uncovered"],
        "gaps": gaps,
        "ratio": (counts["covered"] / total) if total else None,
        "rows": rows,
    }


def _dedupe_entries(document: dict[str, Any]) -> list[dict[str, Any]]:
    removed: list[dict[str, Any]] = []
    for group in _as_list(document.get("dedupe")):
        if not isinstance(group, dict):
            continue
        for item in _as_list(group.get("removed")):
            if isinstance(item, dict):
                removed.append(item)
    return removed


def _cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _table(headers: Iterable[str], rows: Iterable[Iterable[Any]]) -> str:
    header = "| " + " | ".join(_cell(item) for item in headers) + " |"
    divider = "| " + " | ".join("---" for _ in headers) + " |"
    body = ["| " + " | ".join(_cell(item) for item in row) + " |" for row in rows]
    return "\n".join([header, divider, *body])


def _link(path: str, label: str | None = None) -> str:
    return f"[{label or path}](<{path}>)"


def _sorted_findings(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        (record for record in records if isinstance(record, dict)),
        key=lambda item: (
            -SEVERITY_RANK.get(str(item.get("severity")), 0),
            str(item.get("id")),
        ),
    )


def _status_records(data: RunData, status: str) -> list[dict[str, Any]]:
    return [item for item in _as_list(data.findings.get("findings")) if item.get("status") == status]


def _evidence_links(record: dict[str, Any]) -> str:
    links = [
        _link(str(item.get("path")), str(item.get("id")))
        for item in _as_list(record.get("evidence"))
        if isinstance(item, dict) and item.get("path")
    ]
    return ", ".join(links) if links else "-"


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _run_section(data: RunData) -> str:
    metadata = data.metadata
    target = _mapping(metadata.get("target"))
    target_name = target.get("name") or "not recorded"
    base_url = target.get("base_url")
    scope = target.get("scope")
    revision = _mapping(metadata.get("revision"))
    operator = _mapping(metadata.get("operator"))
    plan = _mapping(metadata.get("plan"))
    rows = [
        ("Run id", data.run_id),
        ("Target", target_name or "not recorded"),
        ("Base URL", base_url or "-"),
        ("Scope", scope or "-"),
        ("Suite", metadata.get("suite") or "not recorded"),
        ("Plan", plan.get("path") if isinstance(plan, dict) else "-"),
        ("Started", metadata.get("started_at") or "not recorded"),
        ("Ended", metadata.get("ended_at") or "-"),
        (
            "Revision",
            ", ".join(
                f"{key}={value}"
                for key, value in (
                    ("commit", revision.get("commit")),
                    ("branch", revision.get("branch")),
                    ("fixture", revision.get("fixture_revision")),
                )
                if value
            )
            or "-",
        ),
        (
            "Operator",
            ", ".join(str(value) for value in (operator.get("agent"), operator.get("model"), operator.get("provider")) if value)
            or operator.get("name")
            or "-",
        ),
    ]
    return "## Run\n\n" + _table(("Field", "Value"), rows)


def _summary_section(data: RunData) -> str:
    counts = _rendered_counts(data)
    coverage = _coverage_view(data)
    ratio = coverage["ratio"]
    coverage_text = f"{coverage['covered']}/{coverage['boundaries']}" if coverage["boundaries"] else "not recorded"
    if ratio is not None:
        coverage_text += f" ({ratio:.0%})"
    verified = sum(1 for item in data.evidence if item["integrity"] == "verified")
    rows = [
        ("Findings", counts["total"]),
        ("Confirmed (verified evidence)", counts["confirmed"]),
    ]
    if counts["excluded_confirmed"]:
        rows.append(("Confirmed claims excluded (invalid evidence)", counts["excluded_confirmed"]))
    rows.extend(
        [
            ("Needs validation", counts["needs_validation"]),
            ("Rejected", counts["rejected"]),
            ("Trust boundaries", coverage["boundaries"]),
            ("Covered boundaries (verified evidence)", coverage_text),
            ("Unresolved coverage gaps", len(coverage["gaps"])),
            ("Evidence records verified", f"{verified}/{len(data.evidence)}" if data.evidence else "none"),
        ]
    )
    return "## Summary\n\n" + _table(("Metric", "Value"), rows)


def _before_after_section(data: RunData) -> str:
    current = [item for item in _as_list(data.findings.get("findings")) if isinstance(item, dict)]
    removed = _dedupe_entries(data.findings)
    after = _rendered_counts(data)
    removed_counts = _counts(removed)
    before = {
        key: after.get(key, 0) + removed_counts.get(key, 0)
        for key in ("total", "confirmed", "needs_validation", "rejected")
    }
    distinct_after = len({findings_module.fingerprint(item) for item in current})
    rows = [
        ("Candidate records", before["total"], after["total"]),
        ("Confirmed", before["confirmed"], after["confirmed"]),
        ("Needs validation", before["needs_validation"], after["needs_validation"]),
        ("Rejected", before["rejected"], after["rejected"]),
        ("Distinct fingerprints", distinct_after, distinct_after),
        ("Duplicate records removed", "-", len(removed)),
    ]
    return (
        "## Before / after dedupe\n\n"
        "Before counts are candidate records prior to dedupe and evidence review. "
        "After dedupe counts only confirmed records whose evidence is present and hash-verified.\n\n"
        + _table(("Metric", "Before dedupe", "After dedupe"), rows)
    )


def _findings_section(data: RunData, status: str, heading: str) -> str:
    records = _valid_confirmed(data) if status == "confirmed" else _status_records(data, status)
    records = _sorted_findings(records)
    lines = [f"## {heading}", ""]
    if not records:
        return "\n".join(lines + ["None."])
    rows = [
        (
            record.get("id"),
            record.get("severity"),
            record.get("title"),
            record.get("asset"),
            record.get("entrypoint"),
            _evidence_links(record),
        )
        for record in records
    ]
    lines.append(_table(("ID", "Severity", "Title", "Asset", "Entrypoint", "Evidence"), rows))
    return "\n".join(lines)


def _excluded_confirmed_section(data: RunData) -> str:
    records = _sorted_findings(_invalid_confirmed(data))
    if not records:
        return ""
    rows = [
        (
            record.get("id"),
            record.get("severity"),
            record.get("title"),
            record.get("asset"),
            record.get("entrypoint"),
            _evidence_links(record),
            _record_evidence_state(record, data.integrity),
        )
        for record in records
    ]
    return (
        "## Confirmed claims excluded from counts\n\n"
        "These records are `confirmed` in `findings.json`, but their supporting evidence is "
        "missing or fails its hash check. They are not counted as confirmed, recall or verified "
        "coverage until the evidence is restored or the claim is downgraded.\n\n"
        + _table(("ID", "Severity", "Title", "Asset", "Entrypoint", "Evidence", "Evidence state"), rows)
    )


def _coverage_section(data: RunData) -> str:
    coverage = _coverage_view(data)
    lines = [
        "## Trust-boundary coverage",
        "",
        f"Covered {coverage['covered']} of {coverage['boundaries']} boundaries with verified evidence "
        f"({coverage['excluded']} excluded, {coverage['unverified']} unverified, "
        f"{coverage['uncovered']} uncovered).",
        "",
    ]
    if not coverage["rows"]:
        lines.append("No coverage ledger was recorded.")
        return "\n".join(lines)
    lines.append(_table(("Boundary", "Name", "Status", "Executed probes", "Evidence"), coverage["rows"]))
    lines.extend(["", "### Unresolved coverage gaps", ""])
    if not coverage["gaps"]:
        lines.append("No unresolved coverage gaps were recorded.")
    else:
        lines.append(
            _table(
                ("Boundary", "Status", "Reason"),
                [(gap["id"], gap["status"], gap["reason"]) for gap in coverage["gaps"]],
            )
        )
    return "\n".join(lines)


def _evidence_section(data: RunData) -> str:
    lines = ["## Evidence index", ""]
    if not data.evidence:
        return "\n".join(lines + ["No evidence records."])
    rows = []
    for item in data.evidence:
        integrity = item["integrity"]
        if integrity != "verified":
            integrity = f"**{integrity}**"
        rows.append(
            (
                item.get("id"),
                item.get("kind"),
                _link(str(item.get("path")), str(item.get("path"))),
                str(item.get("sha256") or "")[:12],
                item.get("producer"),
                item.get("timestamp"),
                integrity,
            )
        )
    lines.append(_table(("Evidence", "Kind", "Path", "SHA-256", "Producer", "Timestamp", "Integrity"), rows))
    problems = [item for item in data.evidence if item["integrity"] != "verified"]
    if problems:
        lines.extend(["", "Cell text marked in bold failed integrity checks; rerun or remove the claim."])
    return "\n".join(lines)


def _artifacts_section(data: RunData) -> str:
    expected = (
        "findings.json",
        "coverage-ledger.json",
        "run-metadata.json",
        "plan.json",
        "threat-model.md",
        "state.json",
        "evidence",
        "logs",
    )
    rows = []
    for name in expected:
        target = data.path / name
        rows.append((name, "present" if target.exists() else "missing"))
    return "## Artifacts\n\n" + _table(("Artifact", "Status"), rows)


def render_report(data: RunData, *, now: datetime | None = None) -> str:
    sections = [
        f"# Assessment report — {data.run_id}",
        "",
        f"Generated by `sak report` at {_now(now)}. Authorized assessment evidence only.",
        "",
        _run_section(data),
        _summary_section(data),
        _before_after_section(data),
        _findings_section(data, "confirmed", "Confirmed findings"),
        _excluded_confirmed_section(data),
        _findings_section(data, "needs_validation", "Findings needing validation"),
        _findings_section(data, "rejected", "Rejected records"),
        _coverage_section(data),
        _evidence_section(data),
        _artifacts_section(data),
    ]
    if data.warnings:
        sections.append("## Warnings\n\n" + "\n".join(f"- {warning}" for warning in data.warnings))
    sections.append(
        "## Method note\n\n"
        "A finding is confirmed only with evidence. `needs_validation` records keep an open "
        "question and next action; rejected records keep a reason. Unresolved evidence does not "
        "count as coverage, and scope exclusions are listed as gaps rather than silently dropped."
    )
    text = "\n\n".join(sections) + "\n"
    text = re.sub(r"\n{3,}", "\n\n", text)
    return findings_module.mask_text(text)


def _finding_detail(record: dict[str, Any], integrity: dict[str, str]) -> str:
    lines = [
        f"### {record.get('id')} — {record.get('title')}",
        "",
        _table(
            ("Field", "Value"),
            (
                ("Status", record.get("status")),
                ("Severity", record.get("severity")),
                ("Fingerprint", record.get("fingerprint") or findings_module.fingerprint(record)),
                ("Asset", record.get("asset")),
                ("Entrypoint", record.get("entrypoint")),
                ("Root cause", record.get("root_cause")),
                ("Principal", record.get("principal")),
                ("Resource", record.get("resource")),
                ("Created", record.get("created_at")),
                ("Updated", record.get("updated_at")),
            ),
        ),
    ]
    if _record_evidence_state(record, integrity) == "invalid":
        lines.extend(
            [
                "",
                "**Rendered as unresolved:** supporting evidence is missing or failed its hash check.",
            ]
        )
    for field, label in (
        ("description", "Description"),
        ("impact", "Impact"),
        ("remediation", "Remediation"),
        ("open_question", "Open question"),
        ("next_action", "Next action"),
        ("reason", "Rejection reason"),
        ("notes", "Notes"),
    ):
        if record.get(field):
            lines.extend(["", f"**{label}.** {record[field]}"])
    cwe = record.get("cwe")
    if cwe:
        lines.extend(["", f"**CWE.** {cwe}"])
    source = record.get("source")
    if isinstance(source, dict) and source:
        rendered = ", ".join(f"{key}={value}" for key, value in sorted(source.items()))
        lines.extend(["", f"**Source.** {rendered}"])
    evidence = [item for item in _as_list(record.get("evidence")) if isinstance(item, dict)]
    lines.extend(["", "**Evidence.**", ""])
    if evidence:
        rows = []
        for item in evidence:
            state = integrity.get(str(item.get("id")), "missing")
            if state != "verified":
                state = f"**{state}**"
            rows.append(
                (
                    item.get("id"),
                    item.get("kind"),
                    _link(str(item.get("path")), str(item.get("path"))),
                    item.get("sha256"),
                    item.get("producer"),
                    item.get("timestamp"),
                    state,
                )
            )
        lines.append(
            _table(
                ("ID", "Kind", "Path", "SHA-256", "Producer", "Timestamp", "Integrity"),
                rows,
            )
        )
    else:
        lines.append("No evidence records.")
    history = [item for item in _as_list(record.get("status_history")) if isinstance(item, dict)]
    if history:
        lines.extend(["", "**Status history.**", ""])
        lines.append(
            _table(
                ("From", "To", "At", "Actor", "Reason"),
                [(item.get("from"), item.get("to"), item.get("at"), item.get("actor"), item.get("reason") or "-") for item in history],
            )
        )
    return "\n".join(lines)


def render_details(data: RunData) -> str:
    records = _sorted_findings(_as_list(data.findings.get("findings")))
    lines = [
        f"# Findings detail — {data.run_id}",
        "",
        f"{len(records)} record(s). Every finding keeps its fingerprint, fields, evidence hashes and status history.",
        "",
    ]
    if not records:
        lines.append("No findings were recorded.")
    else:
        lines.append(
            "\n\n".join(_finding_detail(record, data.integrity) for record in records)
        )
    return findings_module.mask_text("\n".join(lines) + "\n")


def render_needs_validation(data: RunData) -> str:
    records = _sorted_findings(_status_records(data, "needs_validation"))
    blocked = _sorted_findings(_invalid_confirmed(data))
    lines = [
        f"# Needs validation — {data.run_id}",
        "",
        "Open leads and confirmed claims whose evidence is missing or fails its hash check. "
        "None of these count as recall or verified coverage until evidence is attached and a "
        "verifier confirms the issue.",
        "",
    ]
    if not records:
        lines.append("No findings need validation.")
    for record in records:
        lines.extend(
            [
                f"## {record.get('id')} — {record.get('title')}",
                "",
                _table(
                    ("Field", "Value"),
                    (
                        ("Severity", record.get("severity")),
                        ("Asset", record.get("asset")),
                        ("Entrypoint", record.get("entrypoint")),
                        ("Root cause", record.get("root_cause")),
                        ("Principal", record.get("principal")),
                        ("Resource", record.get("resource")),
                        ("Open question", record.get("open_question") or "**missing**"),
                        ("Next action", record.get("next_action") or "**missing**"),
                        ("Evidence", _evidence_links(record)),
                    ),
                ),
                "",
            ]
        )
    if blocked:
        lines.extend(
            [
                "## Confirmed claims blocked by evidence",
                "",
                "These records remain `confirmed` in `findings.json` but are excluded from the "
                "report's confirmed count and verified coverage. Restore the evidence or downgrade "
                "the verdict.",
                "",
                _table(
                    ("ID", "Severity", "Title", "Asset", "Evidence state"),
                    [
                        (
                            record.get("id"),
                            record.get("severity"),
                            record.get("title"),
                            record.get("asset"),
                            _record_evidence_state(record, data.integrity),
                        )
                        for record in blocked
                    ],
                ),
                "",
            ]
        )
    return findings_module.mask_text("\n".join(lines).rstrip() + "\n")


def write_reports(run_dir: str | Path, *, now: datetime | None = None) -> dict[str, Path]:
    data = load_run(run_dir)
    documents = {
        "REPORT.md": render_report(data, now=now),
        "FINDINGS-DETAIL.md": render_details(data),
        "NEEDS-VALIDATION.md": render_needs_validation(data),
    }
    written: dict[str, Path] = {}
    for name, text in documents.items():
        path = data.path / name
        path.write_text(text, encoding="utf-8")
        written[name] = path
    return written


def handle(args: argparse.Namespace) -> int:
    written = write_reports(args.run_dir)
    data = load_run(args.run_dir)
    counts = _rendered_counts(data)
    coverage = _coverage_view(data)
    coverage_summary = {
        "boundaries": coverage["boundaries"],
        "covered": coverage["covered"],
        "unverified": coverage["unverified"],
        "excluded": coverage["excluded"],
        "uncovered": coverage["uncovered"],
        "gaps": len(coverage["gaps"]),
        "ratio": coverage["ratio"],
    }
    if args.json:
        util.emit_json(
            {
                "ok": True,
                "run_dir": str(data.path),
                "run_id": data.run_id,
                "written": {name: str(path) for name, path in written.items()},
                "counts": counts,
                "coverage": coverage_summary,
                "warnings": data.warnings,
            }
        )
    else:
        print(f"report: {data.run_id}")
        print(
            f"findings={counts['total']} confirmed={counts['confirmed']} "
            f"needs_validation={counts['needs_validation']} rejected={counts['rejected']} "
            f"excluded_confirmed={counts['excluded_confirmed']}"
        )
        print(
            f"coverage={coverage['covered']}/{coverage['boundaries']} "
            f"unverified={coverage['unverified']} gaps={len(coverage['gaps'])}"
        )
        for name, path in written.items():
            print(f"wrote {path}")
        for warning in data.warnings:
            print(f"warning: {warning}")
    return 0


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("report", help="render reports from a run directory")
    parser.add_argument("run_dir", help="run directory containing findings.json and coverage-ledger.json")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.set_defaults(func=handle)
