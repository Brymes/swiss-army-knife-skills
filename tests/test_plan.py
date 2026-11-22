from __future__ import annotations

import json
from pathlib import Path

import pytest

from sak import catalog as catalog_module
from sak import plan as plan_module
from sak import util
from sak.__main__ import main

FIXTURE = Path(__file__).parent / "fixtures" / "catalog"
TARGET = "http://127.0.0.1:8765"


def _plan(**kwargs):
    loaded = catalog_module.load_catalog(FIXTURE)
    suite = plan_module._suite_data(loaded, "web-blackbox")
    return plan_module.build_plan(loaded, suite, TARGET, **kwargs)


def test_ranking_order_and_roles() -> None:
    built = _plan()
    assert built["roles"]["primary"] == ["fixture-beta", "fixture-alpha"]
    assert built["roles"]["support"] == ["fixture-gamma"]
    assert built["roles"]["fallback"] == ["fixture-delta"]
    assert built["roles"]["brute"] == ["fixture-brute"]

    scores = {candidate["id"]: candidate["score"] for candidate in built["candidates"]}
    assert scores["fixture-beta"] == 14
    assert scores["fixture-alpha"] == 13
    assert scores["fixture-beta"] > scores["fixture-alpha"] > scores["fixture-gamma"] > scores["fixture-delta"]


def test_brute_stays_in_reserve() -> None:
    built = _plan()
    assert "fixture-brute" not in built["roles"]["primary"]
    brute = next(item for item in built["candidates"] if item["id"] == "fixture-brute")
    assert brute["role"] == "brute"
    assert brute["intensity"] == "brute"


def test_hard_filters_exclude_unverified_domain_and_requirements() -> None:
    built = _plan()
    reasons = {item["id"]: item["reason"] for item in built["excluded"]}
    assert "status" in reasons["fixture-unverified"]
    assert "domain" in reasons["fixture-source-only"]
    assert "missing requirement" in reasons["fixture-missing-req"]


def test_missing_requirements_can_be_allowed() -> None:
    built = _plan(allow_missing_requires=True)
    ids = {candidate["id"] for candidate in built["candidates"]}
    assert "fixture-missing-req" in ids


def test_waves_follow_role_order() -> None:
    built = _plan()
    assert [wave["role"] for wave in built["waves"]] == ["primary", "support", "fallback", "brute"]
    assert [wave["ids"] for wave in built["waves"]] == [
        ["fixture-beta", "fixture-alpha"],
        ["fixture-gamma"],
        ["fixture-delta"],
        ["fixture-brute"],
    ]


def test_plan_writes_run_directory(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs" / "fixture"
    built = _plan(run_dir=run_dir)
    written = run_dir / "plan.json"
    assert written.is_file()
    assert built["plan_path"] == str(written)
    on_disk = json.loads(written.read_text(encoding="utf-8"))
    assert on_disk["roles"]["primary"] == ["fixture-beta", "fixture-alpha"]


def test_cli_plan_json(capsys) -> None:
    code = main(
        [
            "plan",
            "--catalog",
            str(FIXTURE),
            "--suite",
            "web-blackbox",
            "--target",
            TARGET,
            "--json",
        ]
    )
    assert code == 0
    built = json.loads(capsys.readouterr().out)
    assert built["suite"]["id"] == "web-blackbox"
    assert built["roles"]["primary"] == ["fixture-beta", "fixture-alpha"]


def test_duplicate_ids_are_rejected_before_planning() -> None:
    loaded = catalog_module.load_catalog(FIXTURE)
    beta = loaded.find("fixture-beta")
    loaded.cards.append(catalog_module.Card("tool", beta.id, beta.path, beta.data))
    suite = plan_module._suite_data(loaded, "web-blackbox")
    with pytest.raises(util.CatalogError, match="duplicate id"):
        plan_module.build_plan(loaded, suite, TARGET)


def test_invalid_standalone_suite_is_rejected(tmp_path: Path, capsys) -> None:
    suite_path = tmp_path / "broken-suite.yaml"
    suite_path.write_text(
        "\n".join(
            [
                "id: broken-suite",
                "name: Broken suite",
                "description: filters must be a mapping.",
                "profile: web-blackbox",
                "filters: not-a-mapping",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    loaded = catalog_module.load_catalog(FIXTURE)
    suite = plan_module._suite_data(loaded, str(suite_path))
    with pytest.raises(util.CatalogError, match="invalid suite"):
        plan_module.build_plan(loaded, suite, TARGET)

    code = main(
        [
            "plan",
            "--catalog",
            str(FIXTURE),
            "--suite",
            str(suite_path),
            "--target",
            TARGET,
            "--json",
        ]
    )
    assert code == 1
    assert "invalid suite" in capsys.readouterr().err


def test_standalone_suite_references_are_resolved(tmp_path: Path, capsys) -> None:
    loaded = catalog_module.load_catalog(FIXTURE)
    original_ids = [card.id for card in loaded.cards]
    base = util.load_yaml(FIXTURE / "suites" / "web-blackbox.yaml")

    cases = [
        ({**base, "include": {"tools": ["fixture-does-not-exist"]}}, "unknown tool"),
        ({**base, "include": {"prompts": ["INV-99"]}}, "unknown prompt"),
        (
            {**base, "filters": {**base["filters"], "exclude_ids": ["fixture-does-not-exist"]}},
            "excludes unknown card",
        ),
    ]
    for suite, message in cases:
        with pytest.raises(util.CatalogError, match=message):
            plan_module.build_plan(loaded, suite, TARGET)

    broken_path = tmp_path / "standalone-broken.yaml"
    broken_path.write_text(
        json.dumps({**base, "include": {"tools": ["fixture-does-not-exist"]}}),
        encoding="utf-8",
    )
    code = main(
        [
            "plan",
            "--catalog",
            str(FIXTURE),
            "--suite",
            str(broken_path),
            "--target",
            TARGET,
            "--json",
        ]
    )
    assert code == 1
    assert "unknown tool" in capsys.readouterr().err
    assert [card.id for card in loaded.cards] == original_ids


def test_valid_standalone_suite_plans(tmp_path: Path) -> None:
    standalone = tmp_path / "web-blackbox.yaml"
    standalone.write_text(
        (FIXTURE / "suites" / "web-blackbox.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    loaded = catalog_module.load_catalog(FIXTURE)
    suite = plan_module._suite_data(loaded, str(standalone))
    built = plan_module.build_plan(loaded, suite, TARGET)
    assert built["roles"]["primary"] == ["fixture-beta", "fixture-alpha"]


