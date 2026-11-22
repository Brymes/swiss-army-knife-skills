"""Command-line entry point for sak."""

from __future__ import annotations

import argparse
import importlib
import sys

from . import __version__, catalog, doctor, engine, plan, util

OPTIONAL_COMMANDS = ("prompts", "hunt", "exploit", "verify", "run", "findings", "report", "eval")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sak",
        description="Portable, ranked security-tool and prompt suite for authorized assessments.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    catalog.add_parser(subparsers)
    plan.add_parser(subparsers)
    doctor.add_parser(subparsers)
    engine.add_parser(subparsers)
    for name in OPTIONAL_COMMANDS:
        try:
            module = importlib.import_module(f".{name}", __package__)
        except ModuleNotFoundError as exc:
            if exc.name != f"{__package__}.{name}":
                raise
            continue
        add_parser = getattr(module, "add_parser", None)
        if callable(add_parser):
            add_parser(subparsers)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except util.SakError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
