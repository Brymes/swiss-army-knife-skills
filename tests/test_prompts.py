from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest
import yaml

from sak import catalog as catalog_module
from sak import prompts, util

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalog"
THREAT_MODEL = Path(__file__).parent / "fixtures" / "prompts" / "threat-model.md"
PAYLOADS = ROOT / "knowledge" / "ssrf" / "payloads.yaml"

INVARIANT_IDS = [f"INV-{number:02d}" for number in range(1, 14)]
VIBE_IDS = [f"VIBE-{number:02d}" for number in range(1, 15)]
SSRF_IDS = [f"SSRF-{number:02d}" for number in range(1, 9)]
LLM_IDS = [f"LLM-{number:02d}" for number in range(1, 9)]
ROLE_IDS = ["MUT-01", "VER-01", "REP-01", "ORCH-01"]
EXPECTED_IDS = INVARIANT_IDS + VIBE_IDS + SSRF_IDS + LLM_IDS + ROLE_IDS


@pytest.fixture(scope="module")
def cards() -> list[catalog_module.Card]:
    return prompts.load_prompts(CATALOG)


@pytest.fixture(scope="module")
def threat_model() -> prompts.ThreatModel:
    return prompts.load_threat_model(THREAT_MODEL)


def _json_stdout(capsys: pytest.CaptureFixture[str]) -> object:
    captured = capsys.readouterr()
    assert captured.err == ""
    return json.loads(captured.out)


def _card_payload(card_id: str = "INV-01") -> dict[str, object]:
    return dict(catalog_module.load_catalog(CATALOG).find(card_id).data)


def _write_prompt_catalog(tmp_path: Path, payloads: list[dict[str, object]]) -> Path:
    prompts_dir = tmp_path / "prompts"
    prompts_dir.mkdir()
    (prompts_dir / "cards.yaml").write_text(
        yaml.safe_dump({"prompts": payloads}, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return tmp_path


def test_every_expected_prompt_id_exists(cards: list[catalog_module.Card]) -> None:
    found = {card.id for card in cards}
    assert set(EXPECTED_IDS) <= found
    assert len(INVARIANT_IDS) == 13
    assert len(VIBE_IDS) == 14
    assert len(SSRF_IDS) == 8
    assert len(LLM_IDS) == 8


def test_ids_are_unique(cards: list[catalog_module.Card]) -> None:
    ids = [card.id for card in cards]
    assert len(ids) == len(set(ids))


def test_catalog_and_cards_validate(cards: list[catalog_module.Card]) -> None:
    loaded = catalog_module.load_catalog(CATALOG)
    assert catalog_module.validate_catalog(loaded) == []
    prompt_cards = loaded.of_type("prompt")
    assert len(prompt_cards) == len(cards) == 47


def test_schema_invalid_card_fails_before_listing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = _card_payload()
    payload["category"] = "not-a-category"
    root = _write_prompt_catalog(tmp_path, [payload])

    with pytest.raises(util.CatalogError, match="invalid catalog"):
        prompts.load_prompts(root)

    assert prompts.main(["list", "--catalog", str(root), "--json"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "invalid catalog" in captured.err
    assert "not-a-category" in captured.err


def test_duplicate_prompt_id_fails_before_show_or_expand(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = _card_payload()
    root = _write_prompt_catalog(tmp_path, [payload, payload])

    with pytest.raises(util.CatalogError, match="duplicate id"):
        prompts.load_prompts(root)

    assert prompts.main(["show", "INV-01", "--catalog", str(root), "--json"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "duplicate id" in captured.err

    assert (
        prompts.main(
            [
                "expand",
                "INV-01",
                "--catalog",
                str(root),
                "--threat-model",
                str(THREAT_MODEL),
                "--json",
            ]
        )
        == 1
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "duplicate id" in captured.err


def test_load_prompt_rejects_duplicate_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    card = catalog_module.load_catalog(CATALOG).find("INV-01")
    monkeypatch.setattr(prompts, "load_prompts", lambda root: [card, card])
    args = argparse.Namespace(catalog=str(CATALOG), id="INV-01")

    with pytest.raises(util.CatalogError, match="duplicate prompt id"):
        prompts._load_prompt(args)


def test_required_sections_are_present(cards: list[catalog_module.Card]) -> None:
    required_text = ("id", "title", "category", "description", "hunter_role", "prompt")
    for card in cards:
        for field in required_text:
            assert isinstance(card.data.get(field), str) and card.data[field].strip(), (card.id, field)
        assert card.data["category"] in prompts.CATEGORIES, card.id
        assert card.data["hunter_role"] in {
            "primary",
            "support",
            "fallback",
            "brute",
            "triage",
            "evidence",
        }, card.id
        assert card.domains, card.id
        assert prompts.card_mutations(card), card.id
        assert prompts.card_lines(card, "evidence"), card.id
        assert prompts.card_lines(card, "stop_conditions"), card.id
        assert prompts.card_lines(card, "safety"), card.id
        assert prompts.card_lines(card, "applies_to"), card.id


def test_no_unresolved_placeholders(cards: list[catalog_module.Card]) -> None:
    for card in cards:
        assert prompts.unresolved_placeholders(card) == [], card.id


def test_every_card_is_authorized_targets_only(cards: list[catalog_module.Card]) -> None:
    for card in cards:
        safety = " ".join(prompts.card_lines(card, "safety")).lower()
        assert "authorized" in safety, card.id
        assert "active" not in safety or "authorized" in safety, card.id


def test_ssrf_payloads_are_active_and_authorized_only() -> None:
    data = yaml.safe_load(PAYLOADS.read_text(encoding="utf-8"))
    assert data["meta"]["active"] is True
    assert data["meta"]["authorized_only"] is True
    payloads = data["payloads"]
    assert len(payloads) >= 20
    ids = [payload["id"] for payload in payloads]
    assert len(ids) == len(set(ids))
    for payload in payloads:
        assert payload["active"] is True, payload["id"]
        assert payload["authorized_only"] is True, payload["id"]
        assert payload["value"], payload["id"]
        assert payload["technique"], payload["id"]
        assert payload["evidence"], payload["id"]
        assert payload["stop_condition"], payload["id"]
        assert "169.254.169.254" not in payload["value"], payload["id"]


def test_payload_pack_covers_required_techniques() -> None:
    data = yaml.safe_load(PAYLOADS.read_text(encoding="utf-8"))
    techniques = {payload["technique"] for payload in data["payloads"]}
    assert {"loopback-literal", "loopback-ipv6", "wildcard-dns", "ip-encoding", "redirect"} <= techniques
    assert {"parser-trick", "protocol", "dns-rebinding"} <= techniques


def test_threat_model_parses_assets_and_boundaries(threat_model: prompts.ThreatModel) -> None:
    assert len(threat_model.assets) >= 5
    assert len(threat_model.trust_boundaries) >= 5
    assert len(threat_model.invariants) >= 5
    assert "User account records" in threat_model.assets[0]
    assert any("loopback" in invariant for invariant in threat_model.invariants)


def test_expansion_is_deterministic(cards: list[catalog_module.Card], threat_model: prompts.ThreatModel) -> None:
    card = next(card for card in cards if card.id == "INV-05")
    first = prompts.expand(card, threat_model)
    second = prompts.expand(card, threat_model)
    assert first == second
    assert first["id"] == "INV-05"
    assert first["hypotheses"] == prompts.build_hypotheses(card, threat_model)
    assert 1 <= len(first["hypotheses"]) <= prompts.DEFAULT_MAX_HYPOTHESES


def test_hypotheses_are_bounded_and_complete(
    cards: list[catalog_module.Card], threat_model: prompts.ThreatModel
) -> None:
    required = {
        "asset",
        "trust_boundary",
        "invariant",
        "suspected_violation",
        "cheapest_test",
        "expected_evidence",
        "stop_condition",
    }
    for card in cards:
        hypotheses = prompts.build_hypotheses(card, threat_model, limit=3)
        assert 1 <= len(hypotheses) <= 3, card.id
        for hypothesis in hypotheses:
            assert required <= set(hypothesis), card.id
            assert all(str(hypothesis[key]).strip() for key in required), card.id


def test_expansion_without_assets_is_marked_inferred(cards: list[catalog_module.Card]) -> None:
    empty = prompts.parse_threat_model("# Empty\n\n## Assets\n", path="<empty>")
    card = next(card for card in cards if card.id == "MUT-01")
    hypotheses = prompts.build_hypotheses(card, empty)
    assert len(hypotheses) == 1
    assert hypotheses[0]["inferred"] is True


def test_render_contains_card_and_threat_model(
    cards: list[catalog_module.Card], threat_model: prompts.ThreatModel
) -> None:
    card = next(card for card in cards if card.id == "INV-01")
    rendered = prompts.render_prompt(card, threat_model)
    assert "INV-01" in rendered
    assert "## Threat model" in rendered
    assert threat_model.assets[0] in rendered
    assert "## Output contract" in rendered
    assert "{{" not in rendered
    assert "${" not in rendered


def test_filter_by_category_domain_and_role(cards: list[catalog_module.Card]) -> None:
    ssrf = prompts.filter_cards(cards, category="ssrf")
    assert [card.id for card in ssrf] == SSRF_IDS
    llm_web = prompts.filter_cards(cards, category="llm", domain="web")
    assert len(llm_web) == 7
    assert all("web" in card.domains for card in llm_web)
    triage = prompts.filter_cards(cards, role="triage")
    assert {card.id for card in triage} == {"VER-01", "ORCH-01"}
    tagged = prompts.filter_cards(cards, tag="idor")
    assert [card.id for card in tagged] == ["VIBE-02"]


def test_cli_list_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert prompts.main(["list", "--json"]) == 0
    rows = _json_stdout(capsys)
    assert isinstance(rows, list)
    ids = {row["id"] for row in rows}
    assert set(EXPECTED_IDS) <= ids
    assert rows == sorted(rows, key=lambda row: row["id"])


def test_cli_list_filters(capsys: pytest.CaptureFixture[str]) -> None:
    assert prompts.main(["list", "--category", "invariant", "--json"]) == 0
    rows = _json_stdout(capsys)
    assert [row["id"] for row in rows] == INVARIANT_IDS


def test_cli_show_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert prompts.main(["show", "INV-01", "--json"]) == 0
    row = _json_stdout(capsys)
    assert row["id"] == "INV-01"
    assert row["category"] == "invariant"
    assert "prompt" in row and row["prompt"].strip()


def test_cli_expand_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert (
        prompts.main(
            [
                "expand",
                "INV-05",
                "--threat-model",
                str(THREAT_MODEL),
                "--json",
            ]
        )
        == 0
    )
    result = _json_stdout(capsys)
    assert result["id"] == "INV-05"
    assert result["hypotheses"]
    assert result["threat_model"]["assets"]
    assert "## Threat model" in result["rendered"]
    assert result["hypotheses"][0]["card"] == "INV-05"


def test_cli_expand_limit(capsys: pytest.CaptureFixture[str]) -> None:
    assert (
        prompts.main(
            [
                "expand",
                "MUT-01",
                "--threat-model",
                str(THREAT_MODEL),
                "--max-hypotheses",
                "2",
                "--json",
            ]
        )
        == 0
    )
    result = _json_stdout(capsys)
    assert len(result["hypotheses"]) == 2


def test_cli_unknown_id_is_a_clean_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert prompts.main(["show", "INV-99", "--json"]) == 1
    captured = capsys.readouterr()
    assert "no prompt card" in captured.err
    assert captured.out == ""


def test_cli_bad_threat_model_is_a_clean_error(capsys: pytest.CaptureFixture[str]) -> None:
    missing = Path(__file__).parent / "fixtures" / "prompts" / "does-not-exist.md"
    assert prompts.main(["expand", "INV-01", "--threat-model", str(missing), "--json"]) == 1
    captured = capsys.readouterr()
    assert "cannot read threat model" in captured.err


def test_vibe_cards_match_the_owner_list(cards: list[catalog_module.Card]) -> None:
    titles = {card.id: card.data["title"].lower() for card in cards}
    expected_fragments = {
        "VIBE-01": "table",
        "VIBE-02": "idor",
        "VIBE-03": "role",
        "VIBE-04": "reset",
        "VIBE-05": "direct api",
        "VIBE-06": "quota",
        "VIBE-07": "credit",
        "VIBE-08": "form",
        "VIBE-09": "open redirect",
        "VIBE-10": "xss",
        "VIBE-11": "ssrf",
        "VIBE-12": "cross-user",
        "VIBE-13": "preview",
        "VIBE-14": "prompt injection",
    }
    for card_id, fragment in expected_fragments.items():
        assert fragment in titles[card_id], card_id


def test_runbook_contains_proof_discipline_and_safety_addendum() -> None:
    runbook = (ROOT / "catalog" / "prompts" / "VIBE-RUNBOOK.md").read_text(encoding="utf-8")
    assert "## Proof discipline" in runbook
    assert "## Safety addendum" in runbook
    assert "confirmed" in runbook and "needs_validation" in runbook and "rejected" in runbook
    assert "Authorized targets only" in runbook or "Authorization" in runbook
