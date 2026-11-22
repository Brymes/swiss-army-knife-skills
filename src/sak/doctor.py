"""Environment doctor.

Reports installed and missing tools with exact install hints.  It never
installs, upgrades or downloads anything; runners only inspect the host.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from functools import lru_cache

from . import util

# Ordered so the report starts with the pinned toolchain.
TOOL_ORDER = (
    "python3.12",
    "uv",
    "git",
    "node",
    "npm",
    "nuclei",
    "docker",
    "docker compose",
    "pwntools",
    "checksec",
    "go",
    "jq",
    "curl",
)

REQUIRED = {"python3.12", "uv", "git"}

HINTS = {
    "python3.12": "uv python install 3.12",
    "uv": "curl -LsSf https://astral.sh/uv/install.sh | sh  # or: brew install uv",
    "git": "xcode-select --install  # or: brew install git",
    "node": "brew install node  # or install Node with nvm",
    "npm": "npm ships with Node; install Node first",
    "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "docker": "brew install --cask docker  # or: brew install --cask orbstack",
    "docker compose": "install Docker Desktop or OrbStack; compose ships with Docker",
    "pwntools": "uv pip install pwntools  # optional, binary work only",
    "checksec": "brew install checksec  # optional, binary work only",
    "go": "brew install go  # optional, needed to build Nuclei and other Go tools",
    "jq": "brew install jq  # optional, convenient for JSON evidence",
    "curl": "install curl with your package manager  # usually preinstalled",
}

LABELS = {
    "python3.12": "Python 3.12",
    "uv": "uv",
    "git": "git",
    "node": "Node.js",
    "npm": "npm",
    "nuclei": "Nuclei",
    "docker": "Docker",
    "docker compose": "Docker Compose",
    "pwntools": "pwntools (pwn)",
    "checksec": "checksec",
    "go": "Go",
    "jq": "jq",
    "curl": "curl",
}

VERSION_ARGS = {
    "uv": ["--version"],
    "git": ["--version"],
    "node": ["--version"],
    "npm": ["--version"],
    "go": ["version"],
    "jq": ["--version"],
    "curl": ["--version"],
}


@dataclass
class ToolStatus:
    name: str
    label: str
    installed: bool
    version: str | None
    path: str | None
    install_hint: str
    required: bool

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def _is_env_var(name: str) -> bool:
    return name.isupper() and "_" in name and all(char.isalnum() or char == "_" for char in name)


def _module_available(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


@lru_cache(maxsize=256)
def is_available(requirement: str) -> bool:
    """Best-effort availability check used by the planner and engine registry."""
    requirement = requirement.strip()
    if not requirement:
        return True
    if _is_env_var(requirement):
        return bool(os.environ.get(requirement))
    lowered = requirement.lower()
    if lowered in {"python", "python3", "python3.12"}:
        return sys.version_info >= (3, 12)
    if lowered in {"docker compose", "docker-compose", "compose"}:
        return shutil.which("docker") is not None
    if lowered == "pwntools":
        return _module_available("pwn")
    if lowered in {"postgres", "postgresql", "psql"}:
        return shutil.which("psql") is not None
    return shutil.which(requirement) is not None


def _version(command: str) -> str | None:
    args = VERSION_ARGS.get(command)
    if not args:
        return None
    try:
        result = subprocess.run(
            [command, *args],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = (result.stdout or result.stderr).strip().splitlines()
    return output[0].strip() if output else None


def detect_tool(name: str) -> ToolStatus:
    """Inspect one tool without changing the host."""
    label = LABELS.get(name, name)
    required = name in REQUIRED
    hint = HINTS.get(name, f"install {name} with your package manager")
    path: str | None = None
    version: str | None = None

    if name == "python3.12":
        installed = sys.version_info >= (3, 12)
        path = sys.executable
        version = platform.python_version()
    elif name == "pwntools":
        installed = _module_available("pwn")
        path = None
        version = None
    elif name == "docker compose":
        installed = shutil.which("docker") is not None
        path = shutil.which("docker")
        version = None
    elif _is_env_var(name):
        installed = bool(os.environ.get(name))
        path = None
        version = None
    else:
        resolved = shutil.which(name)
        installed = resolved is not None
        path = resolved
        version = _version(name) if installed else None

    return ToolStatus(
        name=name,
        label=label,
        installed=installed,
        version=version,
        path=path,
        install_hint=hint,
        required=required,
    )


def collect(extra: list[str] | None = None) -> dict[str, object]:
    """Return the doctor report as plain data (safe to serialize)."""
    names = list(TOOL_ORDER)
    for name in extra or []:
        if name not in names:
            names.append(name)
    tools = [detect_tool(name) for name in names]
    missing = [tool.name for tool in tools if not tool.installed]
    required_missing = [tool.name for tool in tools if tool.required and not tool.installed]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "platform": platform.platform(),
        "python": {
            "version": platform.python_version(),
            "executable": sys.executable,
            "meets_requirement": sys.version_info >= (3, 12),
        },
        "tools": [tool.as_dict() for tool in tools],
        "missing": missing,
        "required_missing": required_missing,
        "ok": not required_missing,
    }


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("doctor", help="report installed and missing tools")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument(
        "--check",
        action="append",
        default=[],
        metavar="NAME",
        help="also check an extra executable or ENV_VAR (repeatable)",
    )
    parser.set_defaults(func=handle)


def handle(args: argparse.Namespace) -> int:
    report = collect(extra=args.check)
    if args.json:
        util.emit_json(report)
        return 0
    rows = [
        [
            tool["label"],
            "installed" if tool["installed"] else "missing",
            tool["version"] or "-",
            tool["path"] or "-",
            tool["install_hint"],
        ]
        for tool in report["tools"]
    ]
    print(util.table(rows, ["TOOL", "STATUS", "VERSION", "PATH", "INSTALL HINT"]))
    installed = sum(1 for tool in report["tools"] if tool["installed"])
    print(f"\n{installed}/{len(report['tools'])} tools installed; python {report['python']['version']}")
    if report["required_missing"]:
        print(f"missing required: {', '.join(report['required_missing'])}")
    elif report["missing"]:
        print(f"optional missing: {', '.join(report['missing'])}")
    return 0
