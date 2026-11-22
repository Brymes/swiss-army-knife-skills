"""Expected-vulnerability verification, coverage and scoring for ``sak verify``.

The verifier is offline and file based.  It reads one target profile's
``expected`` rubric plus the run's ``findings.json``, sanitized ``exploit/*.json``
results and ``hunt/*.json`` records, then scores every expected issue and writes
three derived documents without modifying the source run:

``runs/<run>/verify.json``
    Machine-readable rubric table, verdict/coverage counts, evidence hashes,
    gaps, extras and unknown ids.
``runs/<run>/VERIFICATION.md``
    The human-readable report: rubric table, proof rules, coverage, gaps and the
    "all intended issues" versus "all possible issues" statement.
``runs/<run>/verified-findings.json``
    A findings-schema document that annotates the source findings with the
    rubric id and the verified status.  Source findings are never mutated.

Verdicts are the shared finding vocabulary: ``confirmed`` needs observed proof,
``needs_validation`` is a candidate or partial observation and ``rejected`` is a
disproved attempt.  Coverage adds ``covered`` (confirmed), ``partial``
(candidate/partial), ``missed`` (rejected or never evidenced) and ``deferred``
(rubric entry disabled by default or explicitly excluded).

Mapping is deterministic: an explicit rubric id (exploit check id, finding tag,
``rubric:<ID>`` tag or ``source.prompt``) wins; otherwise a record maps when its
endpoint path and root-cause/class slug both match exactly one rubric entry.
Ambiguous matches stay in ``extras`` and are never double counted.
"""

from __future__ import annotations

import argparse
import json
import re
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from . import findings as findings_module
from . import util

SCHEMA = "sak.blackbox.verify.v1"
# Verdict strength: a proven observation outranks a candidate, which outranks a
# failed attempt.  Absence of any record is not a verdict.
VERDICT_PRIORITY = {"confirmed": 3, "needs_validation": 2, "rejected": 1, "none": 0}
COVERAGE = ("covered", "partial", "missed", "deferred")
EXPLOIT_ACTION_CLASS = {
    "sql_injection": "sql-injection",
    "command_injection": "command-injection",
    "upload": "unrestricted-upload",
    "file_upload_rce": "unrestricted-upload",
    "reflected_xss": "xss-reflected",
    "stored_xss": "xss-stored",
    "idor": "idor",
    "business_logic": "business-logic",
}
INTENDED_STATEMENT = (
    "All {expected} intended issues in the {profile} rubric were scored: "
    "{covered} covered, {partial} partial, {missed} missed, {deferred} deferred."
)
POSSIBLE_STATEMENT = (
    "This is not a claim that every possible issue was found. The denominator is the "
    "profile's expected-issue rubric; findings and checks outside it are reported as "
    "extras and never expand the denominator."
)


class VerifyError(util.SakError):
    """Raised when the rubric, run directory or a source record cannot be scored."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _text(value: Any) -> str:
    return " ".join(str(value or "").split()).strip()


def _slug_key(value: Any) -> str:
    """Fold a class or root-cause slug to a comparable key."""
    return re.sub(r"[^a-z0-9]+", "-", _text(value).lower()).strip("-")


def _path_key(value: Any) -> str:
    """Return the path portion of an endpoint or entrypoint, without query."""
    text = _text(value)
    if not text:
        return ""
    try:
        parsed = urlsplit(text)
    except ValueError:
        return text
    path = parsed.path if (parsed.scheme and parsed.netloc) else text.split("?", 1)[0]
    path = path or "/"
    if len(path) > 1:
        path = path.rstrip("/")
    return path


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise VerifyError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise VerifyError(f"invalid JSON in {path}: {exc}") from exc


def _sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_label(run_dir: Path) -> str:
    return run_dir.name or "run"


# ---------------------------------------------------------------------------
# Rubric
# ---------------------------------------------------------------------------


def load_rubric(profile_path: str | Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Load a profile and return it with its expected-issue rubric.

    Duplicate issue ids are a hard error: the rubric is the coverage
    denominator, so one id must mean one issue.
    """
    path = Path(profile_path).expanduser()
    if not path.is_file():
        raise VerifyError(f"profile not found: {path}")
    data = util.load_yaml(path)
    if not isinstance(data, dict):
        raise VerifyError(f"{path} must contain a profile mapping")
    rubric: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(_list(data.get("expected"))):
        if not isinstance(item, dict):
            raise VerifyError(f"{path}: expected[{index}] must be a mapping")
        issue_id = _text(item.get("id"))
        if not issue_id:
            raise VerifyError(f"{path}: expected[{index}] has no id")
        if issue_id in seen:
            raise VerifyError(f"{path}: duplicate expected issue id {issue_id!r}")
        seen.add(issue_id)
        rubric.append(item)
    return data, rubric


# ---------------------------------------------------------------------------
# Source records
# ---------------------------------------------------------------------------


def load_findings(run_dir: Path) -> tuple[dict[str, Any] | None, list[dict[str, str]]]:
    """Read ``findings.json`` when present and return schema warnings."""
    path = run_dir / findings_module.DEFAULT_FINDINGS
    if not path.is_file():
        return None, []
    document, _ = findings_module.load_document(path)
    issues = findings_module.validate_document(
        document, source=str(path), base_dir=run_dir, check_files=False
    )
    return document, issues


def load_exploit(run_dir: Path) -> list[tuple[Path, dict[str, Any]]]:
    records: list[tuple[Path, dict[str, Any]]] = []
    directory = run_dir / "exploit"
    if not directory.is_dir():
        return records
    for path in sorted(directory.glob("*.json")):
        data = _load_json(path)
        if isinstance(data, dict):
            records.append((path, data))
    return records


def load_hunt(run_dir: Path) -> list[tuple[Path, dict[str, Any]]]:
    records: list[tuple[Path, dict[str, Any]]] = []
    directory = run_dir / "hunt"
    if not directory.is_dir():
        return records
    for path in sorted(directory.glob("*.json")):
        data = _load_json(path)
        if isinstance(data, dict):
            records.append((path, data))
    return records


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


def _issue_keys(issue: dict[str, Any]) -> tuple[str, set[str]]:
    return issue["id"], {_slug_key(issue.get("class"))} - {""}


def _explicit_reference(record: dict[str, Any], issue_id: str) -> bool:
    """Return True when a record names the rubric id explicitly."""
    tags = {_text(tag) for tag in _list(record.get("tags"))}
    if issue_id in tags or f"rubric:{issue_id}" in tags:
        return True
    source = record.get("source")
    if isinstance(source, dict) and _text(source.get("prompt")) == issue_id:
        return True
    for field in ("issue", "expected", "rubric_id"):
        if _text(record.get(field)) == issue_id:
            return True
    return False


def _semantic_match(
    rubric: list[dict[str, Any]],
    *,
    path: Any,
    slug: Any,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Match one path/class pair to exactly one rubric issue."""
    wanted_path = _path_key(path)
    wanted_slug = _slug_key(slug)
    if not wanted_path or not wanted_slug:
        return None, []
    matches = [
        issue
        for issue in rubric
        if _path_key(issue.get("endpoint")) == wanted_path
        and wanted_slug in _issue_keys(issue)[1]
    ]
    if len(matches) == 1:
        return matches[0], []
    if len(matches) > 1:
        return None, [issue["id"] for issue in matches]
    return None, []


def _match_exploit(
    record: dict[str, Any], rubric: list[dict[str, Any]]
) -> tuple[dict[str, Any] | None, list[str]]:
    check = _text(record.get("check"))
    by_id = {issue["id"]: issue for issue in rubric}
    if check in by_id:
        return by_id[check], []
    for issue in rubric:
        if _explicit_reference({**record, "issue": record.get("issue")}, issue["id"]):
            return issue, []
    action_class = EXPLOIT_ACTION_CLASS.get(_text(record.get("action")))
    if action_class:
        matches = [
            issue
            for issue in rubric
            if _slug_key(issue.get("class")) == _slug_key(action_class)
        ]
        if len(matches) == 1 and not _text(record.get("issue")):
            return matches[0], []
    return None, []


def _match_finding(
    finding: dict[str, Any], rubric: list[dict[str, Any]]
) -> tuple[dict[str, Any] | None, list[str]]:
    by_id = {issue["id"]: issue for issue in rubric}
    for issue in rubric:
        if _explicit_reference(finding, issue["id"]):
            return issue, []
    found, ambiguous = _semantic_match(
        rubric,
        path=finding.get("entrypoint"),
        slug=finding.get("root_cause"),
    )
    return found, ambiguous


def _match_candidate(
    candidate: dict[str, Any], rubric: list[dict[str, Any]]
) -> tuple[dict[str, Any] | None, list[str]]:
    by_id = {issue["id"]: issue for issue in rubric}
    candidate_id = _text(candidate.get("id"))
    if candidate_id in by_id:
        return by_id[candidate_id], []
    for issue in rubric:
        if _explicit_reference(candidate, issue["id"]):
            return issue, []
    found, ambiguous = _semantic_match(
        rubric,
        path=candidate.get("entrypoint") or candidate.get("target"),
        slug=candidate.get("root_cause"),
    )
    return found, ambiguous


# ---------------------------------------------------------------------------
# Evidence and verdicts
# ---------------------------------------------------------------------------


def _evidence_ref(
    *,
    source: str,
    label: str,
    path: Path,
    base_dir: Path,
    proof: str = "",
) -> dict[str, Any]:
    try:
        relative = path.resolve().relative_to(base_dir.resolve()).as_posix()
    except ValueError:
        relative = path.as_posix()
    return {
        "source": source,
        "label": label,
        "path": relative,
        "sha256": _sha256(path),
        "proof": proof,
    }


def _finding_evidence(
    finding: dict[str, Any], run_dir: Path
) -> tuple[list[dict[str, Any]], list[str]]:
    """Resolve and hash a finding's evidence; report missing or mismatched files."""
    refs: list[dict[str, Any]] = []
    notes: list[str] = []
    for position, evidence in enumerate(_list(finding.get("evidence"))):
        if not isinstance(evidence, dict) or not _text(evidence.get("path")):
            continue
        raw = Path(_text(evidence["path"])).expanduser()
        resolved = raw if raw.is_absolute() else run_dir / raw
        if not resolved.is_file():
            notes.append(f"evidence[{position}] missing: {evidence.get('path')}")
            continue
        digest = _sha256(resolved)
        recorded = _text(evidence.get("sha256"))
        if recorded and recorded != digest:
            notes.append(f"evidence[{position}] hash mismatch: recorded {recorded[:12]}…")
            continue
        refs.append(
            _evidence_ref(
                source="finding",
                label=_text(evidence.get("id")) or f"evidence[{position}]",
                path=resolved,
                base_dir=run_dir,
                proof=_text(finding.get("title")),
            )
        )
    return refs, notes


def score_finding(
    finding: dict[str, Any], run_dir: Path
) -> tuple[str, list[dict[str, Any]], list[str]]:
    status = _text(finding.get("status"))
    refs, notes = _finding_evidence(finding, run_dir)
    if status == "confirmed":
        if refs:
            return "confirmed", refs, notes
        notes.append("confirmed record has no readable evidence; downgraded to needs_validation")
        return "needs_validation", refs, notes
    if status == "rejected":
        return "rejected", refs, notes
    if status == "needs_validation":
        return "needs_validation", refs, notes
    notes.append(f"unknown finding status {status!r}; treated as needs_validation")
    return "needs_validation", refs, notes


def score_exploit(
    artifact: dict[str, Any], path: Path, run_dir: Path
) -> tuple[str, list[dict[str, Any]], list[str]]:
    status = _text(artifact.get("status"))
    refs: list[dict[str, Any]] = []
    notes: list[str] = []
    embedded = _list(artifact.get("evidence"))
    proof = _text(artifact.get("proof_condition")) or _text(artifact.get("reason"))
    if _text(artifact.get("reason")):
        notes.append(_text(artifact.get("reason")))
    if embedded and path.is_file():
        refs.append(
            _evidence_ref(
                source="exploit",
                label=_text(artifact.get("check")) or path.stem,
                path=path,
                base_dir=run_dir,
                proof=proof,
            )
        )
    if status == "confirmed" and artifact.get("proof") is True and refs:
        return "confirmed", refs, notes
    if status == "confirmed":
        notes.append("confirmed check had no proof flag or embedded evidence; downgraded")
        return "needs_validation", refs, notes
    if status == "rejected":
        return "rejected", refs, notes
    if status == "needs_validation":
        return "needs_validation", refs, notes
    notes.append(f"unknown check status {status!r}; treated as needs_validation")
    return "needs_validation", refs, notes


def _coverage_for(verdict: str, attempted: bool, deferred: bool) -> str:
    if verdict == "confirmed":
        return "covered"
    if verdict == "needs_validation":
        return "partial"
    if verdict == "rejected":
        return "missed"
    return "deferred" if deferred else "missed"


def _is_deferred(issue: dict[str, Any], attempted: bool) -> bool:
    if attempted:
        return False
    if issue.get("deferred") is True or issue.get("excluded") is True:
        return True
    return issue.get("default") is False


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def score_run(
    run_dir: str | Path,
    profile_path: str | Path,
) -> dict[str, Any]:
    """Score every expected issue and return the verification document."""
    directory = Path(run_dir).expanduser()
    if not directory.is_dir():
        raise VerifyError(f"run directory not found: {directory}")
    profile, rubric = load_rubric(profile_path)
    document, finding_warnings = load_findings(directory)
    exploit_records = load_exploit(directory)
    hunt_records = load_hunt(directory)

    by_issue: dict[str, list[dict[str, Any]]] = {issue["id"]: [] for issue in rubric}
    extras: list[dict[str, Any]] = []
    unknown_ids: set[str] = set()
    ambiguous: list[dict[str, Any]] = []

    def add_match(
        *,
        source: str,
        label: str,
        issue: dict[str, Any] | None,
        alternatives: list[str],
        verdict: str,
        refs: list[dict[str, Any]],
        notes: list[str],
        artifact: Path,
    ) -> None:
        if issue is None:
            if alternatives:
                ambiguous.append(
                    {
                        "source": source,
                        "label": label,
                        "candidates": alternatives,
                        "artifact": artifact.relative_to(directory).as_posix(),
                    }
                )
            else:
                extras.append(
                    {
                        "source": source,
                        "label": label,
                        "artifact": artifact.relative_to(directory).as_posix(),
                    }
                )
            return
        by_issue[issue["id"]].append(
            {
                "source": source,
                "label": label,
                "verdict": verdict,
                "evidence": refs,
                "notes": notes,
                "artifact": artifact.relative_to(directory).as_posix(),
            }
        )

    for path, artifact in exploit_records:
        check = _text(artifact.get("check")) or path.stem
        issue, alternatives = _match_exploit(artifact, rubric)
        if issue is None and check not in {item["id"] for item in rubric}:
            unknown_ids.add(check)
        verdict, refs, notes = score_exploit(artifact, path, directory)
        add_match(
            source="exploit",
            label=check,
            issue=issue,
            alternatives=alternatives,
            verdict=verdict,
            refs=refs,
            notes=notes,
            artifact=path,
        )

    for path, record in hunt_records:
        for candidate in _list(record.get("candidates")):
            if not isinstance(candidate, dict):
                continue
            label = _text(candidate.get("id")) or _text(candidate.get("title")) or path.stem
            issue, alternatives = _match_candidate(candidate, rubric)
            refs: list[dict[str, Any]] = []
            if path.is_file():
                refs.append(
                    _evidence_ref(
                        source="hunt",
                        label=label,
                        path=path,
                        base_dir=directory,
                        proof=_text(candidate.get("title")),
                    )
                )
            add_match(
                source="hunt",
                label=label,
                issue=issue,
                alternatives=alternatives,
                verdict="needs_validation",
                refs=refs,
                notes=["hunter candidate; never promoted without observed proof"],
                artifact=path,
            )

    for finding in _list((document or {}).get("findings")):
        if not isinstance(finding, dict):
            continue
        label = _text(finding.get("id")) or _text(finding.get("title"))
        issue, alternatives = _match_finding(finding, rubric)
        verdict, refs, notes = score_finding(finding, directory)
        # Unknown ids surface only when the finding explicitly claims a rubric id.
        for tag in _list(finding.get("tags")):
            text = _text(tag)
            if text.startswith("rubric:") and text.split(":", 1)[1] not in by_issue:
                unknown_ids.add(text.split(":", 1)[1])
        add_match(
            source="finding",
            label=label,
            issue=issue,
            alternatives=alternatives,
            verdict=verdict,
            refs=refs,
            notes=notes,
            artifact=directory / findings_module.DEFAULT_FINDINGS,
        )

    issues: list[dict[str, Any]] = []
    counts = {"confirmed": 0, "needs_validation": 0, "rejected": 0}
    coverage_counts = {name: 0 for name in COVERAGE}
    gaps: list[dict[str, str]] = []
    for issue in rubric:
        records = by_issue[issue["id"]]
        verdict = max(
            (record["verdict"] for record in records),
            key=lambda item: VERDICT_PRIORITY.get(item, 0),
            default="none",
        )
        attempted = bool(records)
        deferred = _is_deferred(issue, attempted)
        coverage = _coverage_for(verdict, attempted, deferred)
        evidence = [
            ref
            for record in records
            for ref in _list(record.get("evidence"))
            if isinstance(ref, dict)
        ]
        notes = [note for record in records for note in _list(record.get("notes"))]
        if verdict in counts:
            counts[verdict] += 1
        coverage_counts[coverage] += 1
        if coverage != "covered":
            gaps.append(
                {
                    "id": issue["id"],
                    "verdict": verdict,
                    "coverage": coverage,
                    "reason": "; ".join(notes)
                    or (
                        "no evidence mapped to this rubric id"
                        if not attempted
                        else f"strongest evidence was {verdict}"
                    ),
                }
            )
        issues.append(
            {
                "id": issue["id"],
                "title": _text(issue.get("title")),
                "class": _text(issue.get("class")),
                "severity": _text(issue.get("severity")),
                "endpoint": _text(issue.get("endpoint")),
                "verdict": verdict,
                "coverage": coverage,
                "attempted": attempted,
                "deferred": deferred,
                "records": [
                    {
                        "source": record["source"],
                        "label": record["label"],
                        "verdict": record["verdict"],
                        "artifact": record["artifact"],
                    }
                    for record in records
                ],
                "evidence": evidence,
                "notes": notes,
            }
        )

    expected = len(rubric)
    ratio = (coverage_counts["covered"] / expected) if expected else None
    target = _text((profile.get("target") or {}).get("id")) or _text(
        (profile.get("target") or {}).get("name")
    )
    statement = {
        "intended_issues": INTENDED_STATEMENT.format(
            expected=expected,
            profile=target or Path(profile_path).name,
            covered=coverage_counts["covered"],
            partial=coverage_counts["partial"],
            missed=coverage_counts["missed"],
            deferred=coverage_counts["deferred"],
        ),
        "possible_issues": POSSIBLE_STATEMENT,
    }
    result: dict[str, Any] = {
        "schema": SCHEMA,
        "run": _run_label(directory),
        "run_dir": str(directory),
        "profile": str(Path(profile_path).expanduser()),
        "target": target,
        "generated_at": _now(),
        "rubric": {
            "expected": expected,
            "confirmed": counts["confirmed"],
            "needs_validation": counts["needs_validation"],
            "rejected": counts["rejected"],
            "unattempted": sum(1 for issue in issues if not issue["attempted"]),
            "coverage": {
                **coverage_counts,
                "ratio": ratio,
            },
        },
        "issues": issues,
        "gaps": gaps,
        "extras": extras,
        "ambiguous": ambiguous,
        "unknown_ids": sorted(unknown_ids),
        "findings_issues": finding_warnings,
        "statement": statement,
        "documents": {
            "json": "verify.json",
            "verification": "VERIFICATION.md",
            "findings": "verified-findings.json",
        },
    }
    result["hashes"] = _document_hashes(directory, issues)
    return result


def _document_hashes(run_dir: Path, issues: list[dict[str, Any]]) -> dict[str, str]:
    """Hash the source artifacts that contributed evidence."""
    hashes: dict[str, str] = {}
    paths = {ref["path"] for issue in issues for ref in issue["evidence"]}
    for relative in sorted(paths):
        path = Path(relative)
        resolved = path if path.is_absolute() else run_dir / path
        if resolved.is_file():
            hashes[relative] = _sha256(resolved)
    return hashes


# ---------------------------------------------------------------------------
# Verified findings document
# ---------------------------------------------------------------------------


def build_verified_findings(
    document: dict[str, Any] | None,
    result: dict[str, Any],
    run_dir: Path,
) -> dict[str, Any]:
    """Annotate source findings with their rubric id and verified status.

    Only observable evidence promotes a record, so a source ``confirmed`` record
    without readable evidence is downgraded.  The source document is not mutated.
    """
    verified: list[dict[str, Any]] = []
    for finding in _list((document or {}).get("findings")):
        if not isinstance(finding, dict):
            continue
        item = deepcopy(finding)
        verdict, _refs, notes = score_finding(item, run_dir)
        issue_id = ""
        for issue in result["issues"]:
            if _explicit_reference(item, issue["id"]):
                issue_id = issue["id"]
                break
        if not issue_id:
            matched, _ = _semantic_match(
                result["issues"],
                path=item.get("entrypoint"),
                slug=item.get("root_cause"),
            )
            if matched is not None:
                issue_id = matched["id"]
        # Keep only evidence that still resolves, so the derived document is valid.
        kept_evidence: list[dict[str, Any]] = []
        for evidence in _list(item.get("evidence")):
            if not isinstance(evidence, dict) or not _text(evidence.get("path")):
                continue
            raw = Path(_text(evidence["path"])).expanduser()
            resolved = raw if raw.is_absolute() else run_dir / raw
            if not resolved.is_file():
                continue
            recorded = _text(evidence.get("sha256"))
            if recorded and recorded != _sha256(resolved):
                continue
            kept_evidence.append(evidence)
        if kept_evidence:
            item["evidence"] = kept_evidence
        else:
            item.pop("evidence", None)
        tags = [_text(tag) for tag in _list(item.get("tags")) if _text(tag)]
        if issue_id:
            tags.append(f"rubric:{issue_id}")
        else:
            tags.append("rubric:extra")
        item["tags"] = sorted(set(tags))
        item["status"] = verdict
        if verdict == "confirmed" and not _list(item.get("evidence")):
            # score_finding already requires readable evidence; keep the guarantee.
            item["status"] = "needs_validation"
        if item["status"] == "needs_validation":
            item.setdefault("open_question", "Does the mapped rubric issue reproduce with observed proof?")
            item.setdefault("next_action", "Replay the mapped check and attach sanitized proof evidence.")
        if item["status"] == "rejected":
            item.setdefault("reason", "the mapped check observed a failure")
        if notes:
            item["notes"] = "; ".join(notes)
        item["updated_at"] = result["generated_at"]
        item["fingerprint"] = findings_module.fingerprint(item)
        verified.append(item)
    return {
        "schema_version": "1",
        "run_id": _text((document or {}).get("run_id")) or result["run"],
        "generated_at": result["generated_at"],
        "target": result.get("target") or "",
        "findings": verified,
        "notes": (
            "Derived by sak verify; source findings.json is unchanged. "
            f"Rubric: {result['rubric']['expected']} expected issues, "
            f"{result['rubric']['confirmed']} confirmed."
        ),
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_verification(result: dict[str, Any]) -> str:
    rubric = result["rubric"]
    coverage = rubric["coverage"]
    lines = [
        f"# Verification — {result['run']}",
        "",
        f"- Target: `{result.get('target') or '-'}`",
        f"- Profile: `{result['profile']}`",
        f"- Generated: {result['generated_at']}",
        f"- Schema: `{SCHEMA}`",
        "",
        "## Result",
        "",
        result["statement"]["intended_issues"],
        "",
        result["statement"]["possible_issues"],
        "",
        "| Metric | Count |",
        "|---|---|",
        f"| Expected issues | {rubric['expected']} |",
        f"| Confirmed | {rubric['confirmed']} |",
        f"| Needs validation | {rubric['needs_validation']} |",
        f"| Rejected | {rubric['rejected']} |",
        f"| Unattempted | {rubric['unattempted']} |",
        f"| Coverage — covered | {coverage['covered']} |",
        f"| Coverage — partial | {coverage['partial']} |",
        f"| Coverage — missed | {coverage['missed']} |",
        f"| Coverage — deferred | {coverage['deferred']} |",
        f"| Coverage ratio | {coverage['ratio'] if coverage['ratio'] is not None else '-'} |",
        "",
        "## Rubric table",
        "",
        "| ID | Class | Verdict | Coverage | Evidence |",
        "|---|---|---|---|---|",
    ]
    for issue in result["issues"]:
        evidence = len(_list(issue.get("evidence")))
        lines.append(
            f"| `{issue['id']}` | {issue['class'] or '-'} | {issue['verdict']} | "
            f"{issue['coverage']} | {len(issue['records'])} record(s), {evidence} hash(es) |"
        )
    lines.extend(["", "## Evidence hashes", ""])
    if result["hashes"]:
        lines.extend(["| Artifact | SHA-256 |", "|---|---|"])
        for path, digest in sorted(result["hashes"].items()):
            lines.append(f"| `{path}` | `{digest}` |")
    else:
        lines.append("No evidence files were mapped to the rubric.")
    lines.extend(["", "## Gaps", ""])
    if result["gaps"]:
        lines.extend(["| ID | Verdict | Coverage | Reason |", "|---|---|---|---|"])
        for gap in result["gaps"]:
            lines.append(
                f"| `{gap['id']}` | {gap['verdict']} | {gap['coverage']} | {gap['reason']} |"
            )
    else:
        lines.append("No gaps: every expected issue is covered.")
    lines.extend(["", "## Extras and unknown ids", ""])
    if result["extras"]:
        lines.append("Records outside the rubric (they do not expand the denominator):")
        lines.append("")
        for extra in result["extras"]:
            lines.append(f"- `{extra['source']}` {extra['label']} — `{extra['artifact']}`")
    else:
        lines.append("- No extra records.")
    if result["ambiguous"]:
        lines.append("")
        for item in result["ambiguous"]:
            lines.append(
                f"- Ambiguous `{item['source']}` {item['label']} matched "
                f"{', '.join(item['candidates'])}; counted as an extra."
            )
    if result["unknown_ids"]:
        lines.append("")
        lines.append(
            "Explicit ids not present in the rubric: " + ", ".join(result["unknown_ids"])
        )
    if result["findings_issues"]:
        lines.append("")
        lines.append("Findings document warnings:")
        lines.append("")
        for issue in result["findings_issues"]:
            lines.append(f"- {issue['id']}: {issue['path']}: {issue['message']}")
    lines.extend(
        [
            "",
            "## Proof rules",
            "",
            "- `confirmed` requires an observed proof: a check that set its proof flag and left",
            "  embedded evidence, or a finding whose evidence files exist and match their hashes.",
            "- `needs_validation` is a candidate or partial observation; it is never promoted.",
            "- `rejected` is a check that ran and disproved its proof condition.",
            "- Coverage counts `covered` only for confirmed issues. `partial` is a candidate,",
            "  `missed` is rejected or never evidenced, and `deferred` is a rubric entry that",
            "  did not run because it was disabled by default or excluded.",
            "",
            "## Documents",
            "",
            "- `verify.json` — machine-readable result.",
            "- `VERIFICATION.md` — this document.",
            "- `verified-findings.json` — source findings annotated with rubric ids and verified",
            "  statuses. `findings.json` and all source evidence are unchanged.",
            "",
        ]
    )
    return "\n".join(lines)


def write_outputs(result: dict[str, Any], run_dir: Path, verified: dict[str, Any]) -> None:
    util.ensure_directory(run_dir)
    (run_dir / "verify.json").write_text(util.dump_json(result), encoding="utf-8")
    (run_dir / "VERIFICATION.md").write_text(render_verification(result), encoding="utf-8")
    (run_dir / "verified-findings.json").write_text(util.dump_json(verified), encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "verify",
        help="score expected issues against run evidence and write verification",
        description=(
            "Map findings, hunt candidates and exploit proofs onto a target profile's "
            "expected-issue rubric. Writes verify.json, VERIFICATION.md and "
            "verified-findings.json without changing source evidence."
        ),
    )
    parser.add_argument("--run", dest="run_dir", required=True, help="run directory to verify")
    parser.add_argument("--profile", required=True, help="target profile YAML with an expected rubric")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.set_defaults(func=handle)


def handle(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir).expanduser()
    result = score_run(run_dir, args.profile)
    document, _ = load_findings(run_dir)
    verified = build_verified_findings(document, result, run_dir)
    write_outputs(result, run_dir, verified)
    if args.json:
        util.emit_json(result)
    else:
        rubric = result["rubric"]
        coverage = rubric["coverage"]
        print(
            f"verify {result['run']}: {rubric['expected']} expected — "
            f"{rubric['confirmed']} confirmed, {rubric['needs_validation']} needs_validation, "
            f"{rubric['rejected']} rejected"
        )
        print(util.table(
            [
                [
                    issue["id"],
                    issue["verdict"],
                    issue["coverage"],
                    issue["class"],
                ]
                for issue in result["issues"]
            ],
            ["ID", "VERDICT", "COVERAGE", "CLASS"],
        ))
        print(
            f"coverage: {coverage['covered']} covered, {coverage['partial']} partial, "
            f"{coverage['missed']} missed, {coverage['deferred']} deferred; "
            f"documents under {run_dir}"
        )
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    """Standalone entry point: ``python -m sak.verify --run DIR --profile PATH``."""
    import sys

    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "verify":
        arguments = arguments[1:]
    parser = argparse.ArgumentParser(
        prog="sak verify",
        description="Score run evidence against a target profile rubric.",
    )
    parser.add_argument("--run", dest="run_dir", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(arguments)
    try:
        return int(handle(args))
    except util.SakError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
