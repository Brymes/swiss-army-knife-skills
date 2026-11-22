"""Catalog loading, validation and querying.

Catalog YAML is the source of truth.  This module discovers cards, checks them
against ``schemas/*.schema.json``, detects duplicate IDs and resolves suite
references.  It never executes a catalog entry.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import util

CARD_TYPES = ("tool", "prompt", "suite", "source", "engine", "model")
SCHEMA_FILES = {
    "tool": "tool.schema.json",
    "prompt": "prompt.schema.json",
    "suite": "suite.schema.json",
    "source": "source.schema.json",
    "engine": "engine.schema.json",
    "model": "model.schema.json",
}
DIRECTORY_TYPES = {
    "tools": "tool",
    "tool": "tool",
    "prompts": "prompt",
    "prompt": "prompt",
    "suites": "suite",
    "suite": "suite",
    "sources": "source",
    "source": "source",
    "engines": "engine",
    "engine": "engine",
    "models": "model",
    "model": "model",
}


@dataclass(frozen=True)
class Card:
    """One loaded YAML card."""

    type: str
    id: str
    path: Path
    data: dict[str, Any]

    @property
    def name(self) -> str:
        return str(self.data.get("name") or self.data.get("title") or self.id)

    @property
    def status(self) -> str:
        return str(self.data.get("status") or "-")

    @property
    def kind(self) -> str:
        return str(self.data.get("kind") or self.type)

    @property
    def domains(self) -> list[str]:
        value = self.data.get("domains")
        return list(value) if isinstance(value, list) else []


@dataclass
class Catalog:
    """A directory of loaded cards plus the root it came from."""

    root: Path
    cards: list[Card] = field(default_factory=list)

    def of_type(self, card_type: str) -> list[Card]:
        return [card for card in self.cards if card.type == card_type]

    def counts(self) -> dict[str, int]:
        counts = {card_type: 0 for card_type in CARD_TYPES}
        for card in self.cards:
            counts[card.type] = counts.get(card.type, 0) + 1
        return counts

    def find(self, card_id: str) -> Card:
        matches = [card for card in self.cards if card.id == card_id]
        if not matches:
            raise util.CatalogError(f"no card with id {card_id!r} under {self.root}")
        if len(matches) > 1:
            raised = ", ".join(str(card.path) for card in matches)
            raise util.CatalogError(f"duplicate id {card_id!r}: {raised}")
        return matches[0]

    def ids(self, card_type: str | None = None) -> set[str]:
        return {
            card.id
            for card in self.cards
            if (card_type is None or card.type == card_type) and isinstance(card.id, str)
        }


def _infer_type(path: Path, data: Any) -> str | None:
    for part in reversed(path.parts[:-1]):
        if part in DIRECTORY_TYPES:
            return DIRECTORY_TYPES[part]
    if path.stem in DIRECTORY_TYPES:
        return DIRECTORY_TYPES[path.stem]
    if not isinstance(data, dict):
        return None
    if data.get("kind") in {"skill", "cli", "platform", "service", "reference", "mcp"}:
        return "tool"
    if data.get("category") or "hunter_role" in data:
        return "prompt"
    if data.get("profile") and "filters" in data:
        return "suite"
    if "commands" in data and "requirements" in data:
        return "engine"
    if "decision" in data and "rationale" in data:
        return "source"
    if data.get("role") and data.get("provider"):
        return "model"
    return None


def _expand_documents(data: Any, card_type: str) -> Iterable[tuple[Any, str]]:
    """Yield ``(payload, id)`` pairs, supporting single cards and lists."""
    plural = f"{card_type}s"
    if isinstance(data, list):
        for item in data:
            yield item, _payload_id(item)
        return
    if not isinstance(data, dict):
        raise util.CatalogError(f"expected a mapping or list of {plural}, got {type(data).__name__}")
    for key in (plural, "cards", "items"):
        value = data.get(key)
        if isinstance(value, list):
            for item in value:
                yield item, _payload_id(item)
            return
    yield data, _payload_id(data)


def _payload_id(payload: Any) -> str:
    if isinstance(payload, dict) and isinstance(payload.get("id"), str):
        return payload["id"]
    return "<missing-id>"


def load_catalog(root: str | Path) -> Catalog:
    """Load every ``*.yaml`` / ``*.yml`` card under *root*.

    Duplicate IDs are not fatal here so that ``validate`` can report all of them
    together.  Callers that need a single card should use :meth:`Catalog.find`.
    """
    base = Path(root).expanduser()
    if not base.exists():
        raise util.CatalogError(f"catalog directory does not exist: {base}")
    catalog = Catalog(root=base)
    paths = sorted(
        path
        for pattern in ("*.yaml", "*.yml")
        for path in base.rglob(pattern)
        if path.is_file()
    )
    if not paths:
        raise util.CatalogError(f"no YAML cards found under {base}")
    for path in paths:
        data = util.load_yaml(path)
        card_type = _infer_type(path.relative_to(base), data)
        if card_type is None:
            raise util.CatalogError(f"cannot determine card type for {path}")
        for payload, card_id in _expand_documents(data, card_type):
            if not isinstance(payload, dict):
                raise util.CatalogError(f"card in {path} is not a mapping")
            catalog.cards.append(Card(card_type, card_id, path, payload))
    return catalog


def schema_for(card_type: str) -> dict[str, Any]:
    filename = SCHEMA_FILES.get(card_type)
    if filename is None:
        raise util.CatalogError(f"no schema for card type {card_type!r}")
    path = util.schemas_dir() / filename
    if not path.is_file():
        raise util.CatalogError(f"schema not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _format_path(parts: Iterable[Any]) -> str:
    rendered = ""
    for part in parts:
        if isinstance(part, int):
            rendered += f"[{part}]"
        else:
            rendered += f".{part}" if rendered else str(part)
    return rendered or "$"


def suite_reference_issues(
    data: Any,
    catalog: Catalog,
    *,
    source: str = "suite",
    card_id: str = "<suite>",
) -> list[dict[str, str]]:
    """Check include/exclude references in one suite against *catalog*."""
    if not isinstance(data, dict):
        return []
    tool_ids = catalog.ids("tool")
    prompt_ids = catalog.ids("prompt")
    issues: list[dict[str, str]] = []

    include = data.get("include")
    if isinstance(include, dict):
        for field, known_ids in (("tools", tool_ids), ("prompts", prompt_ids)):
            references = include.get(field)
            if not isinstance(references, list):
                continue
            for reference in references:
                if not isinstance(reference, str):
                    continue
                if reference not in known_ids:
                    issues.append(
                        {
                            "source": source,
                            "id": card_id,
                            "message": f"suite references unknown {field[:-1]} {reference!r}",
                        }
                    )

    filters = data.get("filters")
    if isinstance(filters, dict):
        excluded_ids = filters.get("exclude_ids")
        if isinstance(excluded_ids, list):
            for excluded in excluded_ids:
                if not isinstance(excluded, str):
                    continue
                if excluded not in tool_ids and excluded not in prompt_ids:
                    issues.append(
                        {
                            "source": source,
                            "id": card_id,
                            "message": f"suite excludes unknown card {excluded!r}",
                        }
                    )
    return issues


def validate_catalog(catalog: Catalog) -> list[dict[str, str]]:
    """Return every schema, duplicate and suite-reference problem."""
    from jsonschema import Draft202012Validator

    issues: list[dict[str, str]] = []
    validators: dict[str, Draft202012Validator] = {}

    for card in catalog.cards:
        if card.type not in validators:
            try:
                validators[card.type] = Draft202012Validator(schema_for(card.type))
            except (json.JSONDecodeError, OSError) as exc:
                issues.append(
                    {
                        "source": str(util.schemas_dir() / SCHEMA_FILES[card.type]),
                        "id": card.type,
                        "message": f"schema cannot be loaded: {exc}",
                    }
                )
                continue
        validator = validators.get(card.type)
        if validator is None:
            issues.append(
                {"source": str(card.path), "id": card.id, "message": f"unknown card type {card.type!r}"}
            )
            continue
        for error in sorted(validator.iter_errors(card.data), key=lambda item: list(item.path)):
            issues.append(
                {
                    "source": str(card.path),
                    "id": card.id,
                    "message": f"{_format_path(error.path)}: {error.message}",
                }
            )

    seen: dict[str, list[Card]] = {}
    for card in catalog.cards:
        key = card.id if isinstance(card.id, str) else repr(card.id)
        seen.setdefault(key, []).append(card)
    for card_id, matches in sorted(seen.items()):
        if len(matches) > 1:
            sources = ", ".join(str(card.path) for card in matches)
            issues.append(
                {"source": sources, "id": card_id, "message": f"duplicate id appears {len(matches)} times"}
            )

    for suite in catalog.of_type("suite"):
        issues.extend(
            suite_reference_issues(
                suite.data,
                catalog,
                source=str(suite.path),
                card_id=str(suite.id),
            )
        )
    return issues


def _issues_summary(issues: list[dict[str, str]], limit: int = 3) -> str:
    shown = issues[:limit]
    summary = "; ".join(f"{issue['id']}: {issue['message']}" for issue in shown)
    remaining = len(issues) - len(shown)
    if remaining > 0:
        summary += f" (+{remaining} more)"
    return summary


def ensure_valid_catalog(catalog: Catalog) -> None:
    """Raise a clean CatalogError instead of planning invalid data."""
    issues = validate_catalog(catalog)
    if issues:
        raise util.CatalogError(f"invalid catalog: {len(issues)} issue(s): {_issues_summary(issues)}")


def validate_suite_data(data: Any, source: str = "suite") -> list[dict[str, str]]:
    """Validate one suite mapping that may come from a standalone YAML file."""
    from jsonschema import Draft202012Validator

    if not isinstance(data, dict):
        return [{"source": source, "id": "<suite>", "message": "suite must be a mapping"}]
    validator = Draft202012Validator(schema_for("suite"))
    issues = []
    for error in sorted(validator.iter_errors(data), key=lambda item: list(item.path)):
        issues.append(
            {
                "source": source,
                "id": str(data.get("id", "<suite>")),
                "message": f"{_format_path(error.path)}: {error.message}",
            }
        )
    return issues


def ensure_valid_suite(
    data: Any,
    source: str = "suite",
    catalog: Catalog | None = None,
) -> None:
    """Raise a clean CatalogError for an invalid standalone or loaded suite.

    When *catalog* is supplied, include/exclude references are resolved against
    it without adding the standalone suite to the catalog.
    """
    issues = validate_suite_data(data, source=source)
    if catalog is not None:
        card_id = str(data.get("id", "<suite>")) if isinstance(data, dict) else "<suite>"
        issues.extend(suite_reference_issues(data, catalog, source=source, card_id=card_id))
    if issues:
        raise util.CatalogError(f"invalid suite: {_issues_summary(issues)}")



def score_card(card: Card) -> int:
    """Explainable integer score: 2*impact + reliability + stealth - effort - noise."""
    ranking = card.data.get("ranking") or {}
    try:
        return (
            2 * int(ranking.get("impact", 0))
            + int(ranking.get("reliability", 0))
            + int(ranking.get("stealth", 0))
            - int(ranking.get("effort", 0))
            - int(ranking.get("noise", 0))
        )
    except (TypeError, ValueError):
        return 0


def _matches(card: Card, args: argparse.Namespace) -> bool:
    if getattr(args, "kind", None) and card.kind != args.kind:
        return False
    if getattr(args, "status", None) and card.status != args.status:
        return False
    if getattr(args, "domain", None) and args.domain not in card.domains:
        return False
    return True


def _list_rows(cards: list[Card]) -> list[list[Any]]:
    return [
        [card.id, card.kind, card.status, ",".join(card.domains), card.data.get("intensity", "-"), score_card(card), card.name]
        for card in sorted(cards, key=lambda item: item.id)
    ]


def _search(catalog: Catalog, query: str) -> list[Card]:
    needle = query.lower()
    matches = []
    for card in catalog.cards:
        haystack = " ".join(
            [
                card.id,
                card.name,
                str(card.data.get("description") or ""),
                " ".join(card.domains),
                " ".join(str(tag) for tag in card.data.get("tags") or []),
            ]
        ).lower()
        if needle in haystack:
            matches.append(card)
    return sorted(matches, key=lambda item: item.id)


def export_catalog(catalog: Catalog) -> dict[str, list[dict[str, Any]]]:
    exported: dict[str, list[dict[str, Any]]] = {}
    for card_type in CARD_TYPES:
        cards = sorted(catalog.of_type(card_type), key=lambda item: item.id)
        if cards:
            exported[card_type] = [card.data for card in cards]
    return exported


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("catalog", help="load and query catalog cards")
    catalog_commands = parser.add_subparsers(dest="catalog_command", required=True)

    def common(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--catalog", default="catalog", help="catalog directory (default: catalog)")
        sub.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    listing = catalog_commands.add_parser("list", help="list cards")
    common(listing)
    listing.add_argument("--kind")
    listing.add_argument("--status")
    listing.add_argument("--domain")
    listing.set_defaults(func=handle_list)

    show = catalog_commands.add_parser("show", help="show one card")
    common(show)
    show.add_argument("id")
    show.set_defaults(func=handle_show)

    search = catalog_commands.add_parser("search", help="search id, name, description or tags")
    common(search)
    search.add_argument("query")
    search.set_defaults(func=handle_search)

    validate = catalog_commands.add_parser("validate", help="validate cards, IDs and suite references")
    common(validate)
    validate.set_defaults(func=handle_validate)

    export = catalog_commands.add_parser("export", help="export the whole catalog")
    common(export)
    export.set_defaults(func=handle_export)

    parser.set_defaults(func=handle_list)


def _load(args: argparse.Namespace) -> Catalog:
    return load_catalog(args.catalog)


def handle_list(args: argparse.Namespace) -> int:
    catalog = _load(args)
    cards = [card for card in catalog.cards if _matches(card, args)]
    cards.sort(key=lambda card: card.id)
    if args.json:
        util.emit_json([card.data for card in cards])
        return 0
    if not cards:
        print("no cards matched")
        return 0
    print(util.table(_list_rows(cards), ["ID", "KIND", "STATUS", "DOMAINS", "INTENSITY", "SCORE", "NAME"]))
    return 0


def handle_show(args: argparse.Namespace) -> int:
    card = _load(args).find(args.id)
    if args.json:
        util.emit_json(card.data)
        return 0
    print(f"# {card.id} ({card.type}) — {card.path}")
    import yaml

    print(yaml.safe_dump(card.data, sort_keys=False, allow_unicode=True).rstrip())
    return 0


def handle_search(args: argparse.Namespace) -> int:
    cards = _search(_load(args), args.query)
    if args.json:
        util.emit_json([card.data for card in cards])
        return 0
    if not cards:
        print(f"no cards matched {args.query!r}")
        return 0
    print(util.table(_list_rows(cards), ["ID", "KIND", "STATUS", "DOMAINS", "INTENSITY", "SCORE", "NAME"]))
    return 0


def handle_validate(args: argparse.Namespace) -> int:
    catalog = _load(args)
    issues = validate_catalog(catalog)
    counts = {key: value for key, value in catalog.counts().items() if value}
    report = {
        "ok": not issues,
        "root": str(catalog.root),
        "cards": len(catalog.cards),
        "counts": counts,
        "errors": issues,
    }
    if args.json:
        util.emit_json(report)
    elif issues:
        for issue in issues:
            print(f"{issue['source']}: {issue['id']}: {issue['message']}")
        print(f"FAIL: {len(issues)} issue(s) in {catalog.root}")
    else:
        counts_text = ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))
        print(f"OK: {len(catalog.cards)} cards ({counts_text}) in {catalog.root}")
    return 0 if not issues else 1


def handle_export(args: argparse.Namespace) -> int:
    exported = export_catalog(_load(args))
    if args.json:
        util.emit_json(exported)
        return 0
    import yaml

    print(yaml.safe_dump(exported, sort_keys=False, allow_unicode=True, width=100).rstrip())
    return 0
