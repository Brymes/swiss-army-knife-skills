"""Offline checks for the engine registry, tool cards, model profiles and source decisions.

Nothing here starts Docker, installs a tool or contacts the network. Engine commands are only ever
printed; refusal tests replace the availability check and the subprocess call.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from sak import catalog as catalog_module
from sak import engine, util
from sak.__main__ import main

ROOT = util.repo_root()
DECISIONS = ROOT / "docs" / "source-decisions.md"
NOTICES = ROOT / "engines" / "THIRD_PARTY_NOTICES.md"
MODELS = ROOT / "catalog" / "models.yaml"

OWNED_TOOL_CARDS = (
    "pentagi",
    "t3mp3st",
    "artex",
    "apple-research",
    "ffuf",
    "sqlmap",
    "zap",
    "playwright",
    "semgrep",
    "gitleaks",
    "trivy",
)

EXPECTED_ENGINES = {"t3mp3st", "pentagi", "artex"}

REQUIRED_SOURCE_LINKS = (
    "pwn-skill",
    "security-audit",
    "Nuclei",
    "PentAGI",
    "Webseek",
    "T3MP3ST",
    "Blackbird",
    "AppleResearch",
    "ARTEX",
    "Zenn article",
    "PortSwigger SSRF",
    "harness book",
    "nip.io",
)

DECISIONS_ALLOWED = {"vendor", "adapter", "engine", "reference", "external"}


def _validator(card_type: str) -> Draft202012Validator:
    return Draft202012Validator(catalog_module.schema_for(card_type))


def _schema_errors(card_type: str, data: object) -> list[str]:
    return [
        f"{'/'.join(map(str, error.path)) or '$'}: {error.message}"
        for error in _validator(card_type).iter_errors(data)
    ]


def _write_fake_engine(root: Path, requirements: list[str], engine_id: str = "fixture-engine") -> Path:
    engines = root / "engines"
    engines.mkdir(parents=True, exist_ok=True)
    data = {
        "id": engine_id,
        "name": "Fixture engine",
        "description": "Offline engine card used by the T9 tests.",
        "license": "MIT",
        "requirements": requirements,
        "commands": {
            "install": "echo install",
            "up": "echo up",
            "down": "echo down",
            "status": "echo status",
        },
    }
    path = engines / f"{engine_id}.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def _decision_rows() -> dict[str, dict[str, str]]:
    """Parse the markdown decision tables into ``{link: {column: value}}``."""
    rows: dict[str, dict[str, str]] = {}
    for line in DECISIONS.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| "):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 6 or cells[0] in {"Link", "---"} or set(cells[0]) <= {"-"}:
            continue
        link, source_type, license_name, decision, url, rationale = cells
        rows[link] = {
            "type": source_type,
            "license": license_name,
            "decision": decision,
            "url": url,
            "rationale": rationale,
        }
    return rows


# --------------------------------------------------------------------------- engine cards


def test_engine_registry_loads_expected_cards() -> None:
    loaded = engine.load_engines(ROOT)
    assert {card.id for card in loaded} == EXPECTED_ENGINES
    for card in loaded:
        assert card.status == "unverified"
        assert card.data["license"]
        assert card.data["source"].startswith("https://")
        assert card.data["requirements"]
        assert set(card.data["commands"]) >= {"install", "up", "down", "status"}


def test_engine_cards_carry_operational_detail() -> None:
    loaded = {card.id: card.data for card in engine.load_engines(ROOT)}
    expected_requirements = {
        "t3mp3st": {"node", "npm"},
        "pentagi": {"docker", "docker compose"},
        "artex": {"docker", "docker compose"},
    }
    for engine_id, requirements in expected_requirements.items():
        data = loaded[engine_id]
        assert requirements <= set(data["requirements"])
        assert data["ports"], engine_id
        assert data["data_paths"], engine_id
        assert all("vendor/external/" in path for path in data["data_paths"]), engine_id
        assert data["models"], engine_id
        assert data["safety"]["external"] is True
        assert data["safety"]["active"] is True
        assert "vendor/external" in data["safety"]["notes"]
        refusal = data["refusal"]
        assert refusal["message"]
        assert refusal["missing_runtime"]
        assert "missing_key" in refusal


def test_engine_list_and_doctor_json(capsys) -> None:
    code = main(["engine", "list", "--root", str(ROOT), "--json"])
    assert code == 0
    listed = json.loads(capsys.readouterr().out)
    assert {item["id"] for item in listed} == EXPECTED_ENGINES
    assert all("ready" in item and "missing" in item for item in listed)

    code = main(["engine", "doctor", "--root", str(ROOT), "--json"])
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert {item["id"] for item in report} == EXPECTED_ENGINES
    assert all(item["requirements"] for item in report)


def test_engine_list_and_doctor_with_fake_card(tmp_path: Path, capsys) -> None:
    _write_fake_engine(tmp_path, ["python3"])

    code = main(["engine", "list", "--root", str(tmp_path), "--json"])
    assert code == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed[0]["id"] == "fixture-engine"
    assert listed[0]["ready"] is True

    code = main(["engine", "doctor", "fixture-engine", "--root", str(tmp_path), "--json"])
    assert code == 0
    doctor_report = json.loads(capsys.readouterr().out)
    assert doctor_report[0]["ready"] is True
    assert doctor_report[0]["requirements"][0]["install_hint"]


def test_engine_dry_run_is_the_default(tmp_path: Path, monkeypatch) -> None:
    _write_fake_engine(tmp_path, ["python3"])

    def fail(*args, **kwargs):
        raise AssertionError("dry run must not execute a command")

    monkeypatch.setattr(engine.subprocess, "run", fail)
    for action in engine.ENGINE_ACTIONS:
        report = engine.run_action(tmp_path, "fixture-engine", action)
        assert report["dry_run"] is True
        assert report["ok"] is True
        assert report["commands"] == [f"echo {action}"]


@pytest.mark.parametrize(
    ("requirement", "reason_fragment"),
    [
        ("docker", "docker"),
        ("docker compose", "docker compose"),
        ("node", "node"),
        ("postgres", "postgres"),
        ("OPENAI_API_KEY", "OPENAI_API_KEY"),
    ],
)
def test_execute_refuses_missing_runtime_with_exit_2(
    tmp_path: Path, capsys, monkeypatch, requirement: str, reason_fragment: str
) -> None:
    _write_fake_engine(tmp_path, [requirement])
    monkeypatch.setattr(engine.doctor, "is_available", lambda name: False)

    def fail(*args, **kwargs):
        raise AssertionError("subprocess must not run when a requirement is missing")

    monkeypatch.setattr(engine.subprocess, "run", fail)

    code = main(
        ["engine", "up", "fixture-engine", "--root", str(tmp_path), "--execute", "--json"]
    )
    assert code == 2
    report = json.loads(capsys.readouterr().out)
    assert report["refused"] is True
    assert report["ok"] is False
    assert reason_fragment in report["reason"]
    assert report["hints"]


def test_execute_runs_when_requirements_are_present(tmp_path: Path, monkeypatch) -> None:
    _write_fake_engine(tmp_path, ["python3"])
    calls: list[str] = []

    class Completed:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(command, **kwargs):
        calls.append(command)
        return Completed()

    monkeypatch.setattr(engine.subprocess, "run", fake_run)
    report = engine.run_action(tmp_path, "fixture-engine", "status", execute=True)
    assert report["ok"] is True
    assert calls == ["echo status"]


def test_invalid_engine_card_is_rejected(tmp_path: Path) -> None:
    path = _write_fake_engine(tmp_path, ["python3"])
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    del data["commands"]
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    with pytest.raises(util.EngineError):
        engine.load_engines(tmp_path)


# --------------------------------------------------------------------------- tool cards


def test_owned_tool_cards_validate() -> None:
    for card_id in OWNED_TOOL_CARDS:
        path = ROOT / "catalog" / "tools" / f"{card_id}.yaml"
        assert path.is_file(), path
        data = util.load_yaml(path)
        assert _schema_errors("tool", data) == [], card_id
        assert data["id"] == card_id
        assert data["license"]
        assert data["sources"] and all(source["url"].startswith("https://") for source in data["sources"])
        assert "adapter" in data
        assert data["safety"]["active"] in (True, False)
        assert data["ranking"]["impact"] >= 1


def test_tool_cards_keep_brute_reserves_out_of_primary() -> None:
    for card_id in ("ffuf", "sqlmap"):
        data = util.load_yaml(ROOT / "catalog" / "tools" / f"{card_id}.yaml")
        assert data["intensity"] == "brute"
        assert "primary" not in (data.get("roles") or [])
        assert "brute" in (data.get("roles") or [])


def test_active_engines_are_marked_intrusive_and_external() -> None:
    for card_id in ("pentagi", "t3mp3st", "artex"):
        data = util.load_yaml(ROOT / "catalog" / "tools" / f"{card_id}.yaml")
        assert data["kind"] == "platform"
        assert data["status"] == "unverified"
        assert data["safety"]["active"] is True
        assert data["safety"]["intrusive"] is True
        assert "vendor/external" in data["safety"]["notes"]


def test_apple_research_is_reference_only() -> None:
    data = util.load_yaml(ROOT / "catalog" / "tools" / "apple-research.yaml")
    assert data["kind"] == "reference"
    assert data["safety"]["active"] is False
    assert "no license" in data["license"].lower()
    assert data["adapter"] is None
    assert "command" not in data["install"]


# --------------------------------------------------------------------------- models


def test_model_cards_validate_and_cover_the_four_roles() -> None:
    payload = util.load_yaml(MODELS)
    cards = payload["models"]
    for card in cards:
        assert _schema_errors("model", card) == [], card.get("id")
        assert card["description"].strip()

    roles = {card["role"] for card in cards}
    assert {"hunting", "generation", "verification", "reporting"} <= roles

    terra = next(card for card in cards if card["id"] == "gpt-6.1-terra")
    assert terra["status"] == "unverified"
    assert "unverified" in terra["notes"].lower()
    assert "operator" in terra["notes"].lower()


def test_refusal_probe_and_operator_report_exist() -> None:
    probe = (ROOT / "knowledge" / "models" / "refusal-probe.md").read_text(encoding="utf-8")
    assert "PROBE-ID: SAK-REFUSAL-01" in probe
    assert "| Date |" in probe
    assert "C1" in probe
    assert "not run" in probe

    operator = (ROOT / "knowledge" / "models" / "operator-reports.md").read_text(encoding="utf-8")
    assert "GPT 6.1 Terra" in operator
    assert "unverified" in operator.lower()
    assert "OPR-01" in operator


# --------------------------------------------------------------------------- source decisions


def test_every_owner_link_has_a_decision_row() -> None:
    rows = _decision_rows()
    missing = [link for link in REQUIRED_SOURCE_LINKS if link not in rows]
    assert missing == [], f"missing source decisions: {missing}"
    for link in REQUIRED_SOURCE_LINKS:
        row = rows[link]
        assert row["type"] in DECISIONS_ALLOWED, link
        assert row["decision"] in DECISIONS_ALLOWED, link
        assert row["license"], link
        assert row["url"].startswith("https://"), link
        assert row["rationale"], link


def test_no_agpl_or_gpl_source_is_decided_vendor_or_adapter() -> None:
    rows = _decision_rows()
    for link, row in rows.items():
        license_name = row["license"].lower()
        if "agpl" in license_name or "gpl" in license_name or license_name == "none declared":
            assert row["decision"] in {"external", "engine", "reference"}, (link, row["decision"])


def test_engine_sources_appear_in_source_decisions() -> None:
    text = DECISIONS.read_text(encoding="utf-8")
    for card in engine.load_engines(ROOT):
        assert card.data["source"] in text, card.id
        if card.data.get("homepage"):
            assert card.data["homepage"] in text, card.id


def test_tool_sources_are_documented() -> None:
    documented = DECISIONS.read_text(encoding="utf-8") + NOTICES.read_text(encoding="utf-8")
    for card_id in OWNED_TOOL_CARDS:
        data = util.load_yaml(ROOT / "catalog" / "tools" / f"{card_id}.yaml")
        for source in data["sources"]:
            assert source["url"] in documented, f"{card_id}: {source['url']}"


def test_third_party_notices_cover_the_engines() -> None:
    notices = NOTICES.read_text(encoding="utf-8")
    for needle in ("T3MP3ST", "PentAGI", "ARTEX", "AGPL-3.0", "MIT"):
        assert needle in notices


# --------------------------------------------------------------------------- hygiene


def test_no_credential_like_values_in_t9_artifacts() -> None:
    pattern = re.compile(
        r"(sk-[A-Za-z0-9]{10,}|ghp_[A-Za-z0-9]{10,}|AKIA[A-Z0-9]{12,}|xox[baprs]-[A-Za-z0-9-]{10,}"
        r"|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
    )
    paths = [
        *(ROOT / "engines").rglob("*.yaml"),
        *(ROOT / "engines").rglob("*.md"),
        *(ROOT / "engines").rglob("*.sh"),
        *(ROOT / "knowledge" / "models").rglob("*.md"),
        ROOT / "docs" / "engines.md",
        ROOT / "docs" / "models.md",
        DECISIONS,
        MODELS,
        *(ROOT / "catalog" / "tools" / f"{card_id}.yaml" for card_id in OWNED_TOOL_CARDS),
    ]
    for path in paths:
        text = Path(path).read_text(encoding="utf-8")
        assert pattern.search(text) is None, f"credential-like value in {path}"


def test_engine_scripts_are_dry_run_by_default() -> None:
    script = (ROOT / "engines" / "scripts" / "engine.sh").read_text(encoding="utf-8")
    assert "--execute" in script
    assert "dry run" in script
    host_check = (ROOT / "engines" / "scripts" / "host-check.sh").read_text(encoding="utf-8")
    assert "never installs" in host_check.lower()


# --------------------------------------------------------------------------- wrapper


WRAPPER = ROOT / "engines" / "scripts" / "engine.sh"


def _stub(bin_dir: Path, name: str, body: str) -> Path:
    path = bin_dir / name
    path.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _wrapper_env(bin_dir: Path, **extra: str) -> dict[str, str]:
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    for key in ("SAK_TARGET", "SAK_LEGION_HOST", "SAK_ROOT"):
        env.pop(key, None)
    env.update(extra)
    return env


def _run_wrapper(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sh", str(WRAPPER), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=False,
    )


def test_wrapper_passes_a_local_argument_vector(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "uv.log"
    _stub(bin_dir, "uv", f'printf "%s\\n" "$PWD" >> "{log}"\nfor a in "$@"; do printf "%s\\n" "$a" >> "{log}"; done')
    env = _wrapper_env(bin_dir)

    dry = _run_wrapper(["up", "pentagi"], env)
    assert dry.returncode == 0
    assert "uv run sak engine up pentagi" in dry.stdout
    assert not log.exists(), "a dry run must not execute uv"

    run = _run_wrapper(["up", "pentagi", "--execute"], env)
    assert run.returncode == 0
    lines = log.read_text(encoding="utf-8").splitlines()
    assert lines[0] == str(ROOT)
    assert lines[1:] == ["run", "sak", "engine", "up", "pentagi", "--execute"]


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["list"], "uv run sak engine list"),
        (["doctor"], "uv run sak engine doctor"),
        (["doctor", "pentagi"], "uv run sak engine doctor pentagi"),
    ],
)
def test_wrapper_dry_run_uses_the_engine_subcommand(
    tmp_path: Path, args: list[str], expected: str
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _stub(bin_dir, "uv", "exit 0")
    result = _run_wrapper(args, _wrapper_env(bin_dir))
    assert result.returncode == 0
    assert expected in result.stdout


@pytest.mark.parametrize(
    ("args", "argv"),
    [
        (["status", "t3mp3st", "--execute"], ["run", "sak", "engine", "status", "t3mp3st", "--execute"]),
        (["install", "pentagi", "--execute"], ["run", "sak", "engine", "install", "pentagi", "--execute"]),
        (["down", "artex", "--execute"], ["run", "sak", "engine", "down", "artex", "--execute"]),
    ],
)
def test_wrapper_executes_the_engine_subcommand(
    tmp_path: Path, args: list[str], argv: list[str]
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "uv.log"
    _stub(bin_dir, "uv", f'for a in "$@"; do printf "%s\\n" "$a" >> "{log}"; done')
    result = _run_wrapper(args, _wrapper_env(bin_dir))
    assert result.returncode == 0
    assert log.read_text(encoding="utf-8").splitlines() == argv


def test_wrapper_rejects_an_injected_engine_id(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "pwned"
    _stub(bin_dir, "uv", 'for a in "$@"; do printf "%s\\n" "$a"; done')
    env = _wrapper_env(bin_dir)
    injected = f"pentagi;touch${{IFS}}{marker};#"

    result = _run_wrapper(["status", injected], env)
    assert result.returncode == 2
    assert "invalid engine id" in result.stderr
    assert not marker.exists()
    assert result.stdout == ""


@pytest.mark.parametrize(
    "args",
    [
        ["up", "pentagi", "extra"],
        ["--bogus"],
        ["up"],
        ["list", "pentagi"],
        ["list", "--execute"],
        ["frobnicate", "pentagi"],
        ["status", "PentAGI"],
        ["status", "pentagi/../x"],
    ],
)
def test_wrapper_rejects_bad_arguments(tmp_path: Path, args: list[str]) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _stub(bin_dir, "uv", "exit 0")
    result = _run_wrapper(args, _wrapper_env(bin_dir))
    assert result.returncode == 2
    assert "error:" in result.stderr


def test_wrapper_quotes_the_remote_root_for_ssh(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    weird_root = tmp_path / "repo dir 'quoted'"
    weird_root.mkdir()
    capture = tmp_path / "remote.sh"
    _stub(bin_dir, "ssh", f'cat > "{capture}"')
    _stub(
        bin_dir,
        "uv",
        'printf "%s\\n" "$PWD"\nfor a in "$@"; do printf "%s\\n" "$a"; done',
    )
    env = _wrapper_env(
        bin_dir,
        SAK_TARGET="legion",
        SAK_LEGION_HOST="legion.test",
        SAK_ROOT=str(weird_root),
    )

    result = _run_wrapper(["status", "pentagi", "--execute"], env)
    assert result.returncode == 0
    script = capture.read_text(encoding="utf-8")
    assert "sh -c" not in script

    # Run the captured remote script through a local shell with the stub uv on PATH.
    executed = subprocess.run(
        ["sh", "-"],
        input=script,
        capture_output=True,
        text=True,
        env=_wrapper_env(bin_dir),
        timeout=30,
        check=False,
    )
    assert executed.returncode == 0, executed.stderr
    lines = executed.stdout.splitlines()
    assert lines[0] == str(weird_root)
    assert lines[1:] == ["run", "sak", "engine", "status", "pentagi", "--execute"]


def test_wrapper_remote_dry_run_never_calls_ssh(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "ssh-called"
    _stub(bin_dir, "ssh", f'touch "{marker}"')
    env = _wrapper_env(
        bin_dir, SAK_TARGET="legion", SAK_LEGION_HOST="legion.test", SAK_ROOT="."
    )

    result = _run_wrapper(["up", "pentagi"], env)
    assert result.returncode == 0
    assert "dry run" in result.stdout
    assert "uv run sak engine up pentagi" in result.stdout
    assert not marker.exists()


def test_wrapper_remote_requires_a_host(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _stub(bin_dir, "ssh", "exit 0")
    env = _wrapper_env(bin_dir, SAK_TARGET="legion")

    result = _run_wrapper(["up", "pentagi"], env)
    assert result.returncode == 1
    assert "SAK_LEGION_HOST" in result.stderr


def test_wrapper_builds_no_shell_strings() -> None:
    script = WRAPPER.read_text(encoding="utf-8")
    assert "sh -c" not in script
    assert "eval " not in script
    assert "set -- $args" not in script


def test_t3mp3st_down_refuses_instead_of_a_broad_pkill() -> None:
    data = util.load_yaml(ROOT / "engines" / "t3mp3st.yaml")
    down = data["commands"]["down"]
    text = " ".join(down) if isinstance(down, list) else str(down)
    assert "pkill" not in text
    assert "refused" in text.lower()
    assert "exit 2" in text


# --------------------------------------------------------------------------- doc claims


def test_source_decisions_separate_policy_from_license_terms() -> None:
    text = DECISIONS.read_text(encoding="utf-8")
    assert "AGPL-3.0 forbids" not in text
    assert "policy" in text.lower()

    rows = _decision_rows()
    assert "unverified" in (rows["ARTEX"]["license"] + rows["ARTEX"]["rationale"]).lower()
    assert "not established" in rows["Blackbird"]["license"].lower()
    assert "prior brief metadata" in rows["Blackbird"]["rationale"].lower()


def test_operator_report_claims_no_capability() -> None:
    payload = util.load_yaml(MODELS)
    card = next(item for item in payload["models"] if item["id"] == "gpt-6.1-terra")
    dumped = json.dumps(card).lower()
    assert "useful" not in dumped
    assert "source text" in dumped
    assert card["status"] == "unverified"


def test_remote_root_docs_and_policy_wording() -> None:
    engines_doc = (ROOT / "docs" / "engines.md").read_text(encoding="utf-8")
    assert "SAK_ROOT='~" not in engines_doc
    assert "SAK_ROOT=/home/" in engines_doc
    assert "absolute path on the remote host" in engines_doc
    assert "not" in engines_doc and "expanded" in engines_doc

    wording = DECISIONS.read_text(encoding="utf-8") + NOTICES.read_text(encoding="utf-8")
    assert "all rights reserved" not in wording.lower()
    assert "GPL-2.0 means" not in wording
