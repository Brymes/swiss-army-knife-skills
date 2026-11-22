"""Small shared helpers for the sak CLI.

The helpers here deliberately stay dependency-light: PyYAML for card IO and the
standard library for rendering.  Nothing in this module executes external tools.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Iterable, Sequence


class SakError(Exception):
    """Base error for expected, user-facing failures.

    CLI entry points catch this instead of letting a traceback escape.
    """


class CatalogError(SakError):
    """Raised when catalog cards cannot be loaded or validated."""


class EngineError(SakError):
    """Raised when an engine card is missing or cannot be operated."""


def repo_root() -> Path:
    """Return the checkout root for an editable/source installation."""
    return Path(__file__).resolve().parents[2]


def schemas_dir() -> Path:
    """Locate the JSON Schema directory.

    Order: ``SAK_SCHEMAS`` override, repository checkout, then a bundled copy if
    a future wheel ships one.
    """
    override = os.environ.get("SAK_SCHEMAS")
    if override:
        return Path(override).expanduser().resolve()
    root = repo_root()
    candidate = root / "schemas"
    if candidate.is_dir():
        return candidate
    return Path(__file__).resolve().parent / "schemas"


def load_yaml(path: Path) -> Any:
    """Load one YAML document, translating parser errors into CatalogError."""
    import yaml

    try:
        with path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle)
    except OSError as exc:
        raise CatalogError(f"cannot read {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise CatalogError(f"invalid YAML in {path}: {exc}") from exc


def dump_json(data: Any) -> str:
    """Deterministic, human-readable JSON used by every ``--json`` output."""
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def emit_json(data: Any) -> None:
    print(dump_json(data), end="")


def table(rows: Iterable[Sequence[Any]], headers: Sequence[str]) -> str:
    """Render a plain-text table without third-party dependencies.

    Empty values become ``-`` so columns stay aligned and readable.
    """
    materialized = [["-" if value in (None, "", []) else str(value) for value in row] for row in rows]
    widths = [len(header) for header in headers]
    for row in materialized:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))
    lines = [
        "  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)).rstrip(),
        "  ".join("-" * width for width in widths).rstrip(),
    ]
    for row in materialized:
        lines.append("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)).rstrip())
    return "\n".join(lines)


def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def csv_list(values: Iterable[str] | None) -> str:
    cleaned = [value for value in (values or []) if value]
    return ",".join(cleaned) if cleaned else "-"


_SECRET_NAME = re.compile(
    r"(?i)(api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret|"
    r"auth(?:orization)?|token|secret|password|passwd|session(?:[_-]?id)?|credential|cookie)"
)

_HEADER_SECRET = re.compile(
    r"(?im)\b(proxy-authorization|authorization|x-api-key|x-auth-token|cookie|set-cookie)"
    r"\s*:\s*[^\r\n]+"
)

_AUTH_SCHEME = re.compile(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{4,}")

_ASSIGNED_SECRET = re.compile(
    r"(?i)(?P<prefix>(?P<quote>[\"']?)\b(?P<key>"
    r"x[_-]?api[_-]?key|x[_-]?auth[_-]?token|api[_-]?key|apikey|access[_-]?key|"
    r"access[_-]?token|refresh[_-]?token|auth[_-]?token|secret[_-]?key|"
    r"private[_-]?key|client[_-]?secret|token|secret|password|passwd|"
    r"session[_-]?id|credential)\b(?P=quote)\s*[:=]\s*)"
    r"(?P<value>\"[^\"]*\"|'[^']*'|[^\s\"',;}]+)"
)


def _mask_assignment(match: re.Match[str]) -> str:
    value = match.group("value")
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        masked_value = f"{value[0]}***{value[0]}"
    else:
        masked_value = "***"
    return f"{match.group('prefix')}{masked_value}"


def is_secret_name(name: str) -> bool:
    """True when an environment variable name is likely to hold a credential."""
    return bool(_SECRET_NAME.search(name))


def secret_env_values(env: dict[str, Any] | None) -> list[str]:
    """Return secret-looking environment values so they can be masked verbatim."""
    values: list[str] = []
    for key, value in (env or {}).items():
        if is_secret_name(str(key)) and value is not None:
            text = str(value)
            if text:
                values.append(text)
    return values


def mask_secrets(text: str | None, secrets: Iterable[str] = ()) -> str:
    """Mask known secret values plus common auth headers and key=value pairs.

    Masking is for display and serialization only.  Callers must pass the
    original, unmasked command and environment to any subprocess.
    """
    if text is None:
        return ""
    masked = str(text)
    for value in sorted({str(item) for item in secrets if item}, key=len, reverse=True):
        masked = masked.replace(value, "***")
    masked = _HEADER_SECRET.sub(r"\1: ***", masked)
    masked = _AUTH_SCHEME.sub(r"\1 ***", masked)
    masked = _ASSIGNED_SECRET.sub(_mask_assignment, masked)
    return masked

