"""Prompt-card loading, filtering and deterministic expansion.

Prompt cards are catalog YAML validated by ``schemas/prompt.schema.json``. This
module only reads them and renders text for a human or another agent. It never
calls a model, an external service or a scanner, and expansion is a pure function
of the card plus a threat-model file.

The ``sak prompts`` command is registered by ``sak.__main__`` when
``prompts.add_parser(subparsers)`` is called. ``main`` also provides a standalone
``python -m sak.prompts`` entry point for tests and dry runs.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from . import catalog as catalog_module
from . import util

CATEGORIES = (
    "invariant",
    "vibe",
    "ssrf",
    "llm",
    "mutation",
    "verification",
    "report",
    "orchestration",
)
DEFAULT_CATALOG = "catalog"
DEFAULT_MAX_HYPOTHESES = 5
MAX_HYPOTHESES = 20
REQUIRED_SECTIONS = ("prompt", "evidence", "stop_conditions", "mutations")

_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(?P<title>.+?)\s*$")
_BULLET = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+(?P<body>.+?)\s*$")
_LABEL = re.compile(
    r"^(?P<label>asset|trust[ _-]?boundary|invariant|requirement|rule)\s*:\s*(?P<body>.+)$",
    re.IGNORECASE,
)
_PLACEHOLDER = re.compile(r"\{\{[^{}]*\}\}|\$\{[^{}]*\}|\b(?:TODO|TBD|FIXME)\b", re.IGNORECASE)


@dataclass(frozen=True)
class ThreatModel:
    """Structured assets, boundaries and invariants parsed from Markdown."""

    path: str
    assets: tuple[str, ...] = ()
    trust_boundaries: tuple[str, ...] = ()
    invariants: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "assets": list(self.assets),
            "trust_boundaries": list(self.trust_boundaries),
            "invariants": list(self.invariants),
        }


def load_prompts(root: str | Path = DEFAULT_CATALOG) -> list[catalog_module.Card]:
    """Load, validate and sort every prompt card under *root*.

    Validation happens before selection or rendering so a schema-invalid edit or a
    duplicate ID fails with a clean catalog error instead of silently choosing one
    card. The existing T1 helpers are reused unchanged.
    """
    loaded = catalog_module.load_catalog(root)
    catalog_module.ensure_valid_catalog(loaded)
    return sorted(loaded.of_type("prompt"), key=lambda card: card.id)


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _mutation_text(mutation: Any) -> str:
    if isinstance(mutation, str):
        return mutation.strip()
    if isinstance(mutation, dict):
        name = _text(mutation.get("name"))
        prompt = _text(mutation.get("prompt"))
        if name and prompt:
            return f"{name}: {prompt}"
        return prompt or name
    return ""


def card_mutations(card: catalog_module.Card) -> list[str]:
    return [
        text
        for text in (_mutation_text(item) for item in card.data.get("mutations") or [])
        if text
    ]


def card_lines(card: catalog_module.Card, field: str) -> list[str]:
    return _string_list(card.data.get(field))


def filter_cards(
    cards: Iterable[catalog_module.Card],
    *,
    category: str | None = None,
    domain: str | None = None,
    role: str | None = None,
    tag: str | None = None,
) -> list[catalog_module.Card]:
    """Filter cards by category, domain, hunter role or tag."""
    selected: list[catalog_module.Card] = []
    for card in cards:
        if category and card.data.get("category") != category:
            continue
        if domain and domain not in card.domains:
            continue
        if role and card.data.get("hunter_role") != role:
            continue
        if tag and tag not in card_lines(card, "tags"):
            continue
        selected.append(card)
    return sorted(selected, key=lambda item: item.id)


def _section_for_heading(title: str) -> str | None:
    lowered = title.lower()
    if "asset" in lowered:
        return "assets"
    if "bound" in lowered or "boundary" in lowered:
        return "trust_boundaries"
    if "invariant" in lowered or "requirement" in lowered or "rule" in lowered:
        return "invariants"
    return None


def _section_for_label(label: str) -> str:
    lowered = label.lower().replace("-", " ").replace("_", " ")
    if lowered.startswith("asset"):
        return "assets"
    if lowered.startswith("trust"):
        return "trust_boundaries"
    return "invariants"


def _append_unique(target: list[str], value: str) -> None:
    cleaned = value.strip().strip("`")
    if not cleaned:
        return
    if cleaned not in target:
        target.append(cleaned)


def parse_threat_model(text: str, *, path: str = "<inline>") -> ThreatModel:
    """Parse a small Markdown threat model deterministically.

    Supports headings named Assets, Trust boundaries and Invariants, plus bullets
    prefixed with ``Asset:``, ``Trust boundary:`` or ``Invariant:``. Bullets with
    no label inherit the current heading. Duplicate values keep their first
    position.
    """
    sections: dict[str, list[str]] = {
        "assets": [],
        "trust_boundaries": [],
        "invariants": [],
    }
    current: str | None = None
    for raw in text.splitlines():
        heading = _HEADING.match(raw)
        if heading:
            current = _section_for_heading(heading.group("title"))
            continue
        bullet = _BULLET.match(raw)
        if not bullet:
            continue
        body = bullet.group("body")
        label = _LABEL.match(body)
        if label:
            _append_unique(sections[_section_for_label(label.group("label"))], label.group("body"))
        elif current:
            _append_unique(sections[current], body)
    return ThreatModel(
        path=path,
        assets=tuple(sections["assets"]),
        trust_boundaries=tuple(sections["trust_boundaries"]),
        invariants=tuple(sections["invariants"]),
    )


def load_threat_model(path: str | Path) -> ThreatModel:
    """Read and parse a threat-model Markdown file."""
    file_path = Path(path).expanduser()
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise util.CatalogError(f"cannot read threat model {file_path}: {exc}") from exc
    return parse_threat_model(text, path=str(file_path))


def _cycle(values: Sequence[str], index: int, fallback: str) -> str:
    if not values:
        return fallback
    return values[index % len(values)]


def _violation(card: catalog_module.Card, asset: str, boundary: str, invariant: str) -> str:
    category = str(card.data.get("category") or "")
    if category == "invariant":
        return f"A path to {asset} does not enforce '{invariant}' across {boundary}."
    if category == "vibe":
        return f"A low-privilege caller can reach {asset} across {boundary} and bypass '{invariant}'."
    if category == "ssrf":
        return f"A server-side fetch crosses {boundary} to {asset} despite '{invariant}'."
    if category == "llm":
        return f"Untrusted content crosses {boundary} into {asset} and overrides '{invariant}'."
    return f"The control for {asset} may not hold across {boundary} against '{invariant}'."


def build_hypotheses(
    card: catalog_module.Card,
    threat_model: ThreatModel,
    *,
    limit: int = DEFAULT_MAX_HYPOTHESES,
) -> list[dict[str, Any]]:
    """Return bounded, deterministic hypotheses derived from the threat model.

    The function does not invent assets when the model provides them. With no
    assets it emits one explicit, marked-inferred hypothesis so the caller can see
    that the threat model is incomplete.
    """
    bounded = max(1, min(int(limit), MAX_HYPOTHESES))
    mutations = card_mutations(card)
    evidence = card_lines(card, "evidence")
    stops = card_lines(card, "stop_conditions")
    cheapest = mutations[0] if mutations else "Send the smallest request that exercises the invariant."
    expected = evidence[0] if evidence else "A reproducible request or source trace."
    stop = stops[0] if stops else "Stop at the first reproducible proof."

    inferred = not threat_model.assets
    assets = threat_model.assets or ("the target surface",)
    boundaries = threat_model.trust_boundaries or ("the nearest trust boundary",)
    invariants = threat_model.invariants or (str(card.data.get("description") or card.name),)

    hypotheses: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for index in range(min(bounded, len(assets))):
        asset = assets[index]
        boundary = _cycle(boundaries, index, "the nearest trust boundary")
        invariant = _cycle(invariants, index, str(card.data.get("description") or card.name))
        key = (asset, boundary, invariant)
        if key in seen:
            continue
        seen.add(key)
        hypothesis: dict[str, Any] = {
            "asset": asset,
            "trust_boundary": boundary,
            "invariant": invariant,
            "suspected_violation": _violation(card, asset, boundary, invariant),
            "cheapest_test": cheapest,
            "expected_evidence": expected,
            "stop_condition": stop,
            "card": card.id,
        }
        if inferred:
            hypothesis["inferred"] = True
        hypotheses.append(hypothesis)
    return hypotheses


def render_prompt(card: catalog_module.Card, threat_model: ThreatModel | None = None) -> str:
    """Render one card and, optionally, a threat model into stable Markdown text."""
    lines: list[str] = [
        f"# {card.id} — {_text(card.data.get('title')) or card.id}",
        "",
        f"Category: {_text(card.data.get('category')) or '-'}",
        f"Hunter role: {_text(card.data.get('hunter_role')) or '-'}",
        f"Intensity: {_text(card.data.get('intensity')) or '-'}",
        f"Domains: {', '.join(card.domains) or '-'}",
        f"Applies to: {', '.join(card_lines(card, 'applies_to')) or '-'}",
        "",
        f"## Why this card",
        "",
        _text(card.data.get("description")) or "-",
    ]
    when = _text(card.data.get("when_to_use"))
    if when:
        lines.extend(["", "## When to use", "", when])
    lines.extend(["", "## Hunter brief", "", _text(card.data.get("prompt")) or "-"])

    inputs = card_lines(card, "inputs")
    if inputs:
        lines.extend(["", "## Inputs", ""] + [f"- {item}" for item in inputs])

    mutations = card_mutations(card)
    if mutations:
        lines.extend(["", "## Bounded mutations", ""])
        lines.extend(f"{index}. {item}" for index, item in enumerate(mutations, start=1))

    evidence = card_lines(card, "evidence")
    if evidence:
        lines.extend(["", "## Evidence to capture", ""] + [f"- {item}" for item in evidence])

    stops = card_lines(card, "stop_conditions")
    if stops:
        lines.extend(["", "## Stop conditions", ""] + [f"- {item}" for item in stops])

    safety = card_lines(card, "safety")
    if safety:
        lines.extend(["", "## Safety", ""] + [f"- {item}" for item in safety])

    if threat_model is not None:
        lines.extend(["", "## Threat model", "", f"Source: {threat_model.path}"])
        for heading, values in (
            ("Assets", threat_model.assets),
            ("Trust boundaries", threat_model.trust_boundaries),
            ("Invariants", threat_model.invariants),
        ):
            lines.extend(["", f"### {heading}", ""])
            lines.extend([f"- {value}" for value in values] or ["- (none stated)"])

    lines.extend(
        [
            "",
            "## Output contract",
            "",
            "Return bounded hypotheses only. Each must state asset, trust boundary, invariant,",
            "suspected violation, cheapest test, expected evidence and stop condition. Prefer a",
            "read-only test and keep a benign control. Do not call an external model or service.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def expand(
    card: catalog_module.Card,
    threat_model: ThreatModel,
    *,
    limit: int = DEFAULT_MAX_HYPOTHESES,
) -> dict[str, Any]:
    """Deterministically render a card and its hypotheses for one threat model."""
    return {
        "id": card.id,
        "title": _text(card.data.get("title")),
        "category": _text(card.data.get("category")),
        "domains": card.domains,
        "hunter_role": _text(card.data.get("hunter_role")),
        "threat_model": threat_model.as_dict(),
        "rendered": render_prompt(card, threat_model),
        "mutations": card_mutations(card),
        "stop_conditions": card_lines(card, "stop_conditions"),
        "hypotheses": build_hypotheses(card, threat_model, limit=limit),
    }


def unresolved_placeholders(card: catalog_module.Card) -> list[str]:
    """Return unresolved template markers in the card's human-facing text."""
    fields: list[str] = []
    for key in ("title", "description", "when_to_use", "prompt", "notes"):
        fields.append(_text(card.data.get(key)))
    for key in ("applies_to", "inputs", "evidence", "stop_conditions", "safety", "tags"):
        fields.extend(card_lines(card, key))
    fields.extend(card_mutations(card))
    found: list[str] = []
    for value in fields:
        found.extend(match.group(0) for match in _PLACEHOLDER.finditer(value))
    return found


def _summary(card: catalog_module.Card) -> dict[str, Any]:
    return {
        "id": card.id,
        "title": _text(card.data.get("title")),
        "category": _text(card.data.get("category")),
        "domains": card.domains,
        "hunter_role": _text(card.data.get("hunter_role")),
        "intensity": _text(card.data.get("intensity")),
        "description": _text(card.data.get("description")),
        "applies_to": card_lines(card, "applies_to"),
        "tags": card_lines(card, "tags"),
    }


def _list_rows(cards: Sequence[catalog_module.Card]) -> list[list[Any]]:
    return [
        [
            card.id,
            _text(card.data.get("category")),
            _text(card.data.get("hunter_role")),
            ",".join(card.domains) or "-",
            _text(card.data.get("title")),
        ]
        for card in cards
    ]


def _load_prompt(args: argparse.Namespace) -> catalog_module.Card:
    cards = load_prompts(args.catalog)
    matches = [card for card in cards if card.id == args.id]
    if not matches:
        raise util.CatalogError(f"no prompt card with id {args.id!r} under {args.catalog}")
    if len(matches) > 1:
        paths = ", ".join(str(card.path) for card in matches)
        raise util.CatalogError(f"duplicate prompt id {args.id!r}: {paths}")
    return matches[0]


def handle_list(args: argparse.Namespace) -> int:
    cards = filter_cards(
        load_prompts(args.catalog),
        category=args.category,
        domain=args.domain,
        role=args.role,
        tag=args.tag,
    )
    if args.json:
        util.emit_json([_summary(card) for card in cards])
        return 0
    if not cards:
        print("no prompt cards matched")
        return 0
    print(util.table(_list_rows(cards), ["ID", "CATEGORY", "ROLE", "DOMAINS", "TITLE"]))
    return 0


def handle_show(args: argparse.Namespace) -> int:
    card = _load_prompt(args)
    if args.json:
        util.emit_json(card.data)
        return 0
    print(f"# {card.id} — {card.path}")
    import yaml

    print(yaml.safe_dump(card.data, sort_keys=False, allow_unicode=True, width=100).rstrip())
    return 0


def handle_expand(args: argparse.Namespace) -> int:
    card = _load_prompt(args)
    if args.threat_model:
        threat_model = load_threat_model(args.threat_model)
    else:
        threat_model = ThreatModel(path="<none>")
    result = expand(card, threat_model, limit=args.max_hypotheses)
    if args.json:
        util.emit_json(result)
        return 0
    print(result["rendered"].rstrip())
    print()
    print("## Hypotheses")
    print()
    import yaml

    print(yaml.safe_dump(result["hypotheses"], sort_keys=False, allow_unicode=True, width=100).rstrip())
    return 0


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--catalog",
        default=DEFAULT_CATALOG,
        help=f"catalog directory (default: {DEFAULT_CATALOG})",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    """Register the ``sak prompts`` command with a parent parser."""
    parser = subparsers.add_parser("prompts", help="load, filter and expand prompt cards")
    commands = parser.add_subparsers(dest="prompts_command", required=True)

    listing = commands.add_parser("list", help="list prompt cards")
    _add_common(listing)
    listing.add_argument("--category", choices=CATEGORIES)
    listing.add_argument("--domain")
    listing.add_argument("--role")
    listing.add_argument("--tag")
    listing.set_defaults(func=handle_list)

    show = commands.add_parser("show", help="show one prompt card")
    _add_common(show)
    show.add_argument("id")
    show.set_defaults(func=handle_show)

    expand_parser = commands.add_parser(
        "expand",
        help="render a card with a threat model and deterministic hypotheses",
    )
    _add_common(expand_parser)
    expand_parser.add_argument("id")
    expand_parser.add_argument("--threat-model", help="threat-model Markdown file")
    expand_parser.add_argument(
        "--max-hypotheses",
        type=int,
        default=DEFAULT_MAX_HYPOTHESES,
        help=f"cap hypotheses (default: {DEFAULT_MAX_HYPOTHESES}, max: {MAX_HYPOTHESES})",
    )
    expand_parser.set_defaults(func=handle_expand)

    parser.set_defaults(func=handle_list)


def main(argv: Sequence[str] | None = None) -> int:
    """Standalone entry point: ``python -m sak.prompts`` or ``prompts`` subcommand."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] != "prompts":
        arguments.insert(0, "prompts")
    parser = argparse.ArgumentParser(
        prog="sak prompts",
        description="Load, filter and expand authorized-assessment prompt cards.",
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
