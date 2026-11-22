from __future__ import annotations

import json
import shutil
from pathlib import Path

from sak import catalog as catalog_module
from sak import util
from sak.__main__ import main

FIXTURE = Path(__file__).parent / "fixtures" / "catalog"


def _duplicate_catalog(tmp_path: Path) -> Path:
    tools = tmp_path / "tools"
    tools.mkdir()
    source = FIXTURE / "tools" / "fixture-alpha.yaml"
    shutil.copyfile(source, tools / "a.yaml")
    shutil.copyfile(source, tools / "b.yaml")
    return tmp_path


def test_fixture_catalog_loads_and_validates() -> None:
    loaded = catalog_module.load_catalog(FIXTURE)
    assert loaded.counts()["tool"] == 8
    assert loaded.counts()["suite"] == 2
    assert catalog_module.validate_catalog(loaded) == []


def test_duplicate_ids_are_reported(tmp_path: Path) -> None:
    loaded = catalog_module.load_catalog(_duplicate_catalog(tmp_path))
    issues = catalog_module.validate_catalog(loaded)
    assert any("duplicate id" in issue["message"] for issue in issues)


def test_schema_failure_is_reported(tmp_path: Path) -> None:
    tools = tmp_path / "tools"
    tools.mkdir()
    text = (FIXTURE / "tools" / "fixture-alpha.yaml").read_text(encoding="utf-8")
    (tools / "bad.yaml").write_text(text.replace("status: verified", "status: bogus"), encoding="utf-8")
    issues = catalog_module.validate_catalog(catalog_module.load_catalog(tmp_path))
    assert issues
    assert any("status" in issue["message"] for issue in issues)


def test_missing_suite_reference_is_reported(tmp_path: Path) -> None:
    tools = tmp_path / "tools"
    suites = tmp_path / "suites"
    tools.mkdir()
    suites.mkdir()
    shutil.copyfile(FIXTURE / "tools" / "fixture-alpha.yaml", tools / "alpha.yaml")
    (suites / "broken.yaml").write_text(
        "\n".join(
            [
                "id: broken",
                "name: Broken suite",
                "description: References a card that does not exist.",
                "profile: web-blackbox",
                "filters:",
                "  statuses: [verified]",
                "include:",
                "  tools: [fixture-does-not-exist]",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    issues = catalog_module.validate_catalog(catalog_module.load_catalog(tmp_path))
    assert any("unknown tool" in issue["message"] for issue in issues)


def test_show_and_search() -> None:
    loaded = catalog_module.load_catalog(FIXTURE)
    assert loaded.find("fixture-alpha").name == "Alpha Scanner"
    matches = [card.id for card in catalog_module._search(loaded, "prober")]
    assert matches == ["fixture-beta"]


def test_malformed_suite_nested_shapes_do_not_crash_validation() -> None:
    valid_suite = util.load_yaml(FIXTURE / "suites" / "web-blackbox.yaml")
    malformed_suites = [
        {**valid_suite, "include": "not-a-mapping"},
        {**valid_suite, "filters": "not-a-mapping"},
        {**valid_suite, "include": {"tools": "not-a-list"}},
        {**valid_suite, "filters": {"exclude_ids": [{"not": "a string"}]}},
    ]
    for index, suite in enumerate(malformed_suites):
        loaded = catalog_module.Catalog(
            root=FIXTURE,
            cards=[catalog_module.Card("suite", f"malformed-{index}", Path("memory.yaml"), suite)],
        )
        issues = catalog_module.validate_catalog(loaded)
        assert issues
        assert all(issue["message"] for issue in issues)


def test_non_string_ids_do_not_crash_validation() -> None:
    valid_suite = util.load_yaml(FIXTURE / "suites" / "web-blackbox.yaml")
    suite = {**valid_suite, "id": 123, "include": {"tools": ["fixture-alpha"]}}
    loaded = catalog_module.Catalog(
        root=FIXTURE,
        cards=[catalog_module.Card("suite", {"unhashable": "id"}, Path("memory.yaml"), suite)],  # type: ignore[arg-type]
    )
    issues = catalog_module.validate_catalog(loaded)
    assert issues


def test_all_schemas_are_valid_json_schema() -> None:
    from jsonschema import Draft202012Validator

    for filename in catalog_module.SCHEMA_FILES.values():
        path = util.schemas_dir() / filename
        assert path.is_file(), filename
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)



def test_cli_list_and_validate_json(capsys) -> None:
    code = main(["catalog", "list", "--catalog", str(FIXTURE), "--json"])
    assert code == 0
    listed = json.loads(capsys.readouterr().out)
    ids = {card["id"] for card in listed}
    assert {"fixture-alpha", "fixture-beta", "fixture-brute"} <= ids

    code = main(["catalog", "validate", "--catalog", str(FIXTURE), "--json"])
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True
    assert report["counts"]["tool"] == 8


def test_cli_show_and_invalid_exit(capsys, tmp_path: Path) -> None:
    code = main(["catalog", "show", "fixture-beta", "--catalog", str(FIXTURE), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["id"] == "fixture-beta"

    code = main(["catalog", "validate", "--catalog", str(_duplicate_catalog(tmp_path))])
    assert code == 1
    assert "duplicate id" in capsys.readouterr().out
