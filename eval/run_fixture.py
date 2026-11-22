#!/usr/bin/env python3
"""Run the deterministic fixture evaluation without the project venv.

Usage mirrors ``uv run sak eval``:

    python3 eval/run_fixture.py
    python3 eval/run_fixture.py --run-dir runs/demo --run-id demo-web-blackbox --artifacts

The launcher adds ``src/`` to ``sys.path`` and calls ``sak.eval``. ``sak.eval``
imports only the standard library, so this works with a plain ``python3``; the
fixture itself is also standard-library only and binds loopback only.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sak import eval as eval_module  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] != "eval":
        arguments.insert(0, "eval")
    return eval_module.main(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
