"""Optional engine registry.

Engine cards describe install/up/down/status commands.  Every action is a dry
run unless ``--execute`` is passed, and a missing runtime produces a clean
refusal instead of a traceback or a partial install.
"""

from __future__ import annotations

import argparse
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import catalog as catalog_module
from . import doctor, util

ENGINE_ACTIONS = ("install", "up", "down", "status")


@dataclass(frozen=True)
class Engine:
    id: str
    path: Path
    data: dict[str, Any]

    @property
    def name(self) -> str:
        return str(self.data.get("name") or self.id)

    @property
    def status(self) -> str:
        return str(self.data.get("status") or "unverified")


def _engine_paths(root: Path) -> list[Path]:
    paths: list[Path] = []
    for base in (root / "engines", root / "catalog" / "engines"):
        if base.is_dir():
            for pattern in ("*.yaml", "*.yml"):
                paths.extend(path for path in base.rglob(pattern) if path.is_file())
    return sorted(set(paths))


def _validate_engine(path: Path, data: dict[str, Any]) -> None:
    from jsonschema import Draft202012Validator

    validator = Draft202012Validator(catalog_module.schema_for("engine"))
    errors = sorted(validator.iter_errors(data), key=lambda item: list(item.path))
    if errors:
        details = "; ".join(f"{'/'.join(map(str, error.path)) or '$'}: {error.message}" for error in errors)
        raise util.EngineError(f"invalid engine card {path}: {details}")


def load_engines(root: str | Path = ".") -> list[Engine]:
    """Load and validate engine cards under ``<root>/engines``."""
    base = Path(root).expanduser()
    if not base.exists():
        raise util.EngineError(f"engine root does not exist: {base}")
    engines: list[Engine] = []
    seen: dict[str, Path] = {}
    for path in _engine_paths(base):
        data = util.load_yaml(path)
        if isinstance(data, dict) and isinstance(data.get("engines"), list):
            payloads = data["engines"]
        elif isinstance(data, list):
            payloads = data
        else:
            payloads = [data]
        for payload in payloads:
            if not isinstance(payload, dict):
                raise util.EngineError(f"engine card in {path} is not a mapping")
            _validate_engine(path, payload)
            engine_id = str(payload.get("id"))
            if engine_id in seen:
                raise util.EngineError(f"duplicate engine id {engine_id!r}: {seen[engine_id]}, {path}")
            seen[engine_id] = path
            engines.append(Engine(engine_id, path, payload))
    return sorted(engines, key=lambda engine: engine.id)


def _requirements(engine: Engine) -> list[dict[str, Any]]:
    statuses = []
    for requirement in engine.data.get("requirements") or []:
        available = doctor.is_available(requirement)
        hint = doctor.HINTS.get(requirement)
        if hint is None and doctor._is_env_var(requirement):
            hint = f"export {requirement}=..."
        statuses.append(
            {
                "requirement": requirement,
                "available": available,
                "install_hint": hint or f"install {requirement}",
            }
        )
    return statuses


def _commands(engine: Engine, action: str) -> list[str]:
    value = (engine.data.get("commands") or {}).get(action)
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def _expand(command: str, engine: Engine, root: Path) -> str:
    cwd = root / engine.data.get("cwd", "") if engine.data.get("cwd") else root
    return command.replace("{root}", str(root)).replace("{engine_root}", str(root)).replace("{cwd}", str(cwd))


def _engine_report(engine: Engine) -> dict[str, Any]:
    requirements = _requirements(engine)
    missing = [item["requirement"] for item in requirements if not item["available"]]
    return {
        "id": engine.id,
        "name": engine.name,
        "status": engine.status,
        "path": str(engine.path),
        "requirements": requirements,
        "missing": missing,
        "ready": not missing,
        "ports": engine.data.get("ports") or [],
        "models": engine.data.get("models") or [],
    }


def _find(engines: list[Engine], engine_id: str) -> Engine:
    matches = [engine for engine in engines if engine.id == engine_id]
    if not matches:
        known = ", ".join(engine.id for engine in engines) or "none"
        raise util.EngineError(f"no engine with id {engine_id!r} (known: {known})")
    return matches[0]


def run_action(
    root: str | Path,
    engine_id: str,
    action: str,
    *,
    execute: bool = False,
) -> dict[str, Any]:
    if action not in ENGINE_ACTIONS:
        raise util.EngineError(f"unknown engine action {action!r}; choose from {', '.join(ENGINE_ACTIONS)}")
    base = Path(root).expanduser()
    engines = load_engines(base)
    engine = _find(engines, engine_id)
    requirements = _requirements(engine)
    missing = [item["requirement"] for item in requirements if not item["available"]]
    base_env = dict(os.environ)
    card_env = {str(key): str(value) for key, value in (engine.data.get("env") or {}).items()}
    effective_env = {**base_env, **card_env}
    secret_values = list(
        dict.fromkeys([*util.secret_env_values(base_env), *util.secret_env_values(card_env)])
    )
    raw_commands = [_expand(command, engine, base) for command in _commands(engine, action)]
    commands = [util.mask_secrets(command, secret_values) for command in raw_commands]

    report: dict[str, Any] = {
        "engine": engine.id,
        "action": action,
        "dry_run": not execute,
        "commands": commands,
        "requirements": requirements,
        "missing": missing,
    }
    if not execute:
        report["ok"] = True
        return report
    if missing:
        report["ok"] = False
        report["refused"] = True
        report["reason"] = f"missing runtime for {engine.id}: {', '.join(missing)}"
        report["hints"] = [
            f"{item['requirement']}: {item['install_hint']}"
            for item in requirements
            if not item["available"]
        ]
        return report
    if not commands:
        report["ok"] = False
        report["refused"] = True
        report["reason"] = f"engine {engine.id} has no {action} command"
        return report

    env = effective_env
    cwd = base / engine.data["cwd"] if engine.data.get("cwd") else base
    results = []
    for command in raw_commands:
        completed = subprocess.run(
            command,
            shell=True,
            cwd=str(cwd),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        results.append(
            {
                "command": util.mask_secrets(command, secret_values),
                "returncode": completed.returncode,
                "stdout": util.mask_secrets(completed.stdout, secret_values),
                "stderr": util.mask_secrets(completed.stderr, secret_values),
            }
        )
        if completed.returncode != 0:
            break
    report["results"] = results
    report["ok"] = all(item["returncode"] == 0 for item in results)
    return report


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("engine", help="inspect and operate optional engines")
    engine_commands = parser.add_subparsers(dest="engine_command", required=True)

    def common(sub: argparse.ArgumentParser) -> None:
        # Repeated on subcommands so options may follow the action, e.g.
        # ``sak engine list --root . --json``.
        sub.add_argument("--root", default=".", help="repository root containing engines/ (default: .)")
        sub.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    listing = engine_commands.add_parser("list", help="list engine cards")
    common(listing)
    listing.set_defaults(func=handle_list)

    doctor_parser = engine_commands.add_parser("doctor", help="check engine requirements")
    common(doctor_parser)
    doctor_parser.add_argument("id", nargs="?", help="engine ID (default: all)")
    doctor_parser.set_defaults(func=handle_doctor)

    for action in ENGINE_ACTIONS:
        action_parser = engine_commands.add_parser(action, help=f"{action} an engine (dry run by default)")
        common(action_parser)
        action_parser.add_argument("id", help="engine ID")
        action_parser.add_argument(
            "--execute",
            action="store_true",
            help="actually run the commands; without this flag only print them",
        )
        action_parser.set_defaults(func=handle_action, action=action)

    parser.set_defaults(func=handle_list)


def handle_list(args: argparse.Namespace) -> int:
    engines = load_engines(args.root)
    reports = [_engine_report(engine) for engine in engines]
    if args.json:
        util.emit_json(reports)
        return 0
    if not reports:
        print(f"no engine cards under {Path(args.root) / 'engines'}")
        return 0
    rows = [
        [item["id"], item["name"], item["status"], "ready" if item["ready"] else "missing", ", ".join(item["missing"])]
        for item in reports
    ]
    print(util.table(rows, ["ID", "NAME", "STATUS", "READY", "MISSING"]))
    return 0


def handle_doctor(args: argparse.Namespace) -> int:
    engines = load_engines(args.root)
    selected = [_find(engines, args.id)] if args.id else engines
    reports = [_engine_report(engine) for engine in selected]
    if args.json:
        util.emit_json(reports)
        return 0
    if not reports:
        print(f"no engine cards under {Path(args.root) / 'engines'}")
        return 0
    for item in reports:
        state = "ready" if item["ready"] else f"missing: {', '.join(item['missing'])}"
        print(f"{item['id']}: {state}")
        for requirement in item["requirements"]:
            mark = "ok" if requirement["available"] else "missing"
            print(f"  {requirement['requirement']:20} {mark}")
            if not requirement["available"]:
                print(f"    hint: {requirement['install_hint']}")
    return 0


def handle_action(args: argparse.Namespace) -> int:
    report = run_action(args.root, args.id, args.action, execute=args.execute)
    if args.json:
        util.emit_json(report)
    elif report.get("refused"):
        print(f"refused: {report['reason']}")
        for hint in report.get("hints") or []:
            print(f"  {hint}")
    elif report["dry_run"]:
        print(f"dry run: {report['engine']} {report['action']}")
        for command in report["commands"]:
            print(f"  $ {command}")
        if report["missing"]:
            print(f"  missing requirements: {', '.join(report['missing'])}")
        print("  pass --execute to run")
    else:
        print(f"ran: {report['engine']} {report['action']}")
        for result in report.get("results") or []:
            print(f"  rc={result['returncode']}  $ {result['command']}")
    return 2 if report.get("refused") else (0 if report.get("ok") else 1)
