"""Portfolio planner.

Turns a suite plus catalog cards into an explainable, role-ranked plan.  The
planner is offline and side-effect free unless ``--run-dir`` is supplied, in
which case it writes ``plan.json`` under that run directory.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import catalog as catalog_module
from . import doctor, util

DEFAULT_BUDGET = {"primary": 3, "support": 4, "fallback": 3, "brute": 1}
ROLE_ORDER = ("primary", "support", "fallback", "brute")
FORMULA = "2*impact + reliability + stealth - effort - noise"


def _suite_data(catalog: catalog_module.Catalog, suite_ref: str) -> dict[str, Any]:
    candidate = Path(suite_ref)
    if candidate.suffix in {".yaml", ".yml"} and candidate.is_file():
        data = util.load_yaml(candidate)
        if not isinstance(data, dict):
            raise util.CatalogError(f"suite file is not a mapping: {candidate}")
        return data
    card = catalog.find(suite_ref)
    if card.type != "suite":
        raise util.CatalogError(f"{suite_ref!r} is a {card.type} card, not a suite")
    return card.data


def _budget(suite: dict[str, Any]) -> dict[str, int]:
    budget = dict(DEFAULT_BUDGET)
    for key, value in (suite.get("budget") or {}).items():
        if key in budget and isinstance(value, int):
            budget[key] = value
    return budget


def _breakdown(card: catalog_module.Card) -> dict[str, int]:
    ranking = card.data.get("ranking") or {}
    return {
        "impact": int(ranking.get("impact", 0)),
        "reliability": int(ranking.get("reliability", 0)),
        "stealth": int(ranking.get("stealth", 0)),
        "effort": int(ranking.get("effort", 0)),
        "noise": int(ranking.get("noise", 0)),
    }


def _hard_filter(
    card: catalog_module.Card,
    suite: dict[str, Any],
    *,
    allow_missing_requires: bool,
) -> str | None:
    filters = suite.get("filters") or {}
    include = suite.get("include") or {}
    included_tools = set(include.get("tools") or [])

    if included_tools and card.id not in included_tools:
        return "not in suite include.tools"
    if card.id in set(filters.get("exclude_ids") or []):
        return "excluded by suite"

    statuses = set(filters.get("statuses") or ["verified"])
    if card.status not in statuses:
        return f"status {card.status!r} not allowed"

    kinds = set(filters.get("kinds") or [])
    if kinds and card.kind not in kinds:
        return f"kind {card.kind!r} not allowed"

    filter_domains = set(filters.get("domains") or suite.get("domains") or [])
    if filter_domains and not filter_domains.intersection(card.domains):
        return f"domain {','.join(card.domains) or '-'} not allowed"

    modes = set(filters.get("modes") or [])
    card_modes = set(card.data.get("modes") or [])
    if modes and card_modes and not modes.intersection(card_modes):
        return f"mode {','.join(sorted(card_modes))} not allowed"

    tags = set(filters.get("tags") or [])
    if tags and not tags.intersection(card.data.get("tags") or []):
        return "missing required tag"

    if not allow_missing_requires:
        requirements = list(dict.fromkeys([*(filters.get("requires") or []), *(card.data.get("requires") or [])]))
        missing = [requirement for requirement in requirements if not doctor.is_available(requirement)]
        if missing:
            return f"missing requirement: {', '.join(missing)}"
    return None


def _candidate(card: catalog_module.Card, role: str) -> dict[str, Any]:
    breakdown = _breakdown(card)
    return {
        "id": card.id,
        "name": card.name,
        "kind": card.kind,
        "status": card.status,
        "domains": card.domains,
        "intensity": card.data.get("intensity") or "normal",
        "role": role,
        "score": catalog_module.score_card(card),
        "formula": FORMULA,
        "breakdown": breakdown,
        "requires": list(card.data.get("requires") or []),
        "adapter": card.data.get("adapter"),
    }


def build_plan(
    catalog: catalog_module.Catalog,
    suite: dict[str, Any],
    target: str,
    *,
    run_dir: str | Path | None = None,
    allow_missing_requires: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build the plan document without writing it (unless *run_dir* is set)."""
    if not target:
        raise util.CatalogError("a target is required")
    catalog_module.ensure_valid_catalog(catalog)
    catalog_module.ensure_valid_suite(suite, catalog=catalog)
    budget = _budget(suite)
    included_tools = set((suite.get("include") or {}).get("tools") or [])

    eligible: list[catalog_module.Card] = []
    excluded: list[dict[str, str]] = []
    for card in catalog.of_type("tool"):
        if included_tools and card.id not in included_tools:
            continue
        reason = _hard_filter(card, suite, allow_missing_requires=allow_missing_requires)
        if reason is None:
            eligible.append(card)
        else:
            excluded.append({"id": card.id, "reason": reason})

    reserve: list[catalog_module.Card] = []
    regular: list[catalog_module.Card] = []
    for card in eligible:
        is_brute = card.data.get("intensity") == "brute" or "brute" in (card.data.get("roles") or [])
        (reserve if is_brute else regular).append(card)

    regular.sort(key=lambda card: (-catalog_module.score_card(card), card.id))
    reserve.sort(key=lambda card: (-catalog_module.score_card(card), card.id))

    roles: dict[str, list[str]] = {role: [] for role in ROLE_ORDER}
    candidates: list[dict[str, Any]] = []
    cursor = 0
    for role in ("primary", "support", "fallback"):
        for card in regular[cursor : cursor + budget[role]]:
            roles[role].append(card.id)
            candidates.append(_candidate(card, role))
        cursor += budget[role]
    for card in regular[cursor:]:
        excluded.append({"id": card.id, "reason": "outside role budget"})

    for card in reserve[: budget["brute"]]:
        roles["brute"].append(card.id)
        candidates.append(_candidate(card, "brute"))
    for card in reserve[budget["brute"] :]:
        excluded.append({"id": card.id, "reason": "brute reserve full"})

    waves = [
        {"wave": index, "role": role, "ids": roles[role]}
        for index, role in enumerate((role for role in ROLE_ORDER if roles[role]), start=1)
    ]
    generated_at = (now or datetime.now(timezone.utc)).isoformat(timespec="seconds")
    run_id = f"{generated_at.replace(':', '').replace('-', '')}-{suite.get('id', 'suite')}"
    plan: dict[str, Any] = {
        "run_id": run_id,
        "generated_at": generated_at,
        "target": target,
        "suite": {
            "id": suite.get("id"),
            "name": suite.get("name"),
            "profile": suite.get("profile"),
            "budget": budget,
        },
        "filters": suite.get("filters") or {},
        "allow_missing_requires": allow_missing_requires,
        "candidates": candidates,
        "roles": roles,
        "waves": waves,
        "excluded": sorted(excluded, key=lambda item: item["id"]),
        "plan_path": None,
    }

    if run_dir is not None:
        destination = util.ensure_directory(Path(run_dir).expanduser())
        path = destination / "plan.json"
        path.write_text(util.dump_json(plan), encoding="utf-8")
        plan["plan_path"] = str(path)

    return plan


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("plan", help="rank a portfolio for a suite and target")
    parser.add_argument("--catalog", default="catalog", help="catalog directory (default: catalog)")
    parser.add_argument("--suite", required=True, help="suite ID or path to a suite YAML file")
    parser.add_argument("--target", required=True, help="authorized target URL or path")
    parser.add_argument("--run-dir", help="write plan.json under this run directory")
    parser.add_argument(
        "--allow-missing-requires",
        action="store_true",
        help="plan cards even when their runtime requirements are missing",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.set_defaults(func=handle)


def handle(args: argparse.Namespace) -> int:
    loaded = catalog_module.load_catalog(args.catalog)
    suite = _suite_data(loaded, args.suite)
    plan = build_plan(
        loaded,
        suite,
        args.target,
        run_dir=args.run_dir,
        allow_missing_requires=args.allow_missing_requires,
    )
    if args.json:
        util.emit_json(plan)
        return 0
    print(f"suite: {plan['suite']['id']} ({plan['suite']['profile']})")
    print(f"target: {plan['target']}")
    print(f"score: {FORMULA}")
    for wave in plan["waves"]:
        print(f"\nwave {wave['wave']} — {wave['role']}")
        for card_id in wave["ids"]:
            candidate = next(item for item in plan["candidates"] if item["id"] == card_id)
            print(f"  {card_id:24} score={candidate['score']:>3}  {candidate['name']}")
    if plan["excluded"]:
        print(f"\nexcluded: {len(plan['excluded'])}")
        for item in plan["excluded"]:
            print(f"  {item['id']:24} {item['reason']}")
    if plan["plan_path"]:
        print(f"\nplan written: {plan['plan_path']}")
    return 0
