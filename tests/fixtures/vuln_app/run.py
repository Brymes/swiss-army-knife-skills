#!/usr/bin/env python3
"""CLI for the T8 localhost vulnerable fixture.

Examples:
    python3 tests/fixtures/vuln_app/run.py
    python3 tests/fixtures/vuln_app/run.py --check
    python3 tests/fixtures/vuln_app/run.py --reset
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE.parent) not in sys.path:
    sys.path.insert(0, str(HERE.parent))

from vuln_app import app as fixture_app  # noqa: E402
from vuln_app import storage  # noqa: E402

DEFAULT_DB = HERE / "vuln_app.db"


def _counts(db_path: Path) -> tuple[int, int]:
    conn = storage.connect(db_path)
    try:
        users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    finally:
        conn.close()
    return int(users), int(sessions)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SAK T8 localhost vulnerable fixture")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="SQLite path (default: %(default)s)")
    parser.add_argument("--host", default="127.0.0.1", help="bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="bind port (default: 8765)")
    parser.add_argument("--check", action="store_true", help="initialize and verify seed data, then exit")
    parser.add_argument("--reset", action="store_true", help="reset the database to the deterministic seed, then exit")
    args = parser.parse_args(argv)

    try:
        fixture_app.validate_bind_host(args.host)
    except ValueError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2

    if args.reset:
        storage.reset_db(args.db)
        users, sessions = _counts(args.db)
        print(f"reset ok: users={users} sessions={sessions} db={args.db}")
        return 0

    if args.check:
        storage.init_db(args.db)
        users, sessions = _counts(args.db)
        if users != len(storage.SEED_USERS):
            print(f"check failed: expected {len(storage.SEED_USERS)} users, found {users}", file=sys.stderr)
            return 1
        print(
            f"fixture ok: accounts={users} issues=14 "
            f"url=http://{args.host}:{args.port} db={args.db}"
        )
        return 0

    storage.init_db(args.db)
    users, _ = _counts(args.db)
    print(f"serving SAK T8 fixture on http://{args.host}:{args.port} accounts={users} db={args.db}")
    try:
        fixture_app.serve(args.db, args.host, args.port)
    except KeyboardInterrupt:
        print("stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
