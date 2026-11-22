"""SQLite storage and deterministic seed data for the T8 vulnerable fixture.

Standard library only. The fixture is an authorized localhost test target; it
deliberately contains security weaknesses and must never be deployed.
"""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

PASSWORD_SALT = "sak-t8-fixture"

# Fixed evaluator-only accounts. Passwords are intentionally trivial test data.
SEED_USERS = (
    {
        "id": 1,
        "username": "alice",
        "email": "alice@example.test",
        "password": "alice-pw",
        "role": "user",
        "display_name": "Alice",
        "bio": "Account A",
        "credits": 10,
        "ai_uses": 0,
        "ai_quota": 3,
    },
    {
        "id": 2,
        "username": "bob",
        "email": "bob@example.test",
        "password": "bob-pw",
        "role": "user",
        "display_name": "Bob",
        "bio": "Account B",
        "credits": 5,
        "ai_uses": 0,
        "ai_quota": 3,
    },
    {
        "id": 3,
        "username": "admin",
        "email": "admin@example.test",
        "password": "admin-pw",
        "role": "admin",
        "display_name": "Administrator",
        "bio": "Fixture administrator",
        "credits": 100,
        "ai_uses": 0,
        "ai_quota": 100,
    },
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    display_name TEXT NOT NULL DEFAULT '',
    bio TEXT NOT NULL DEFAULT '',
    credits INTEGER NOT NULL DEFAULT 0,
    ai_uses INTEGER NOT NULL DEFAULT 0,
    ai_quota INTEGER NOT NULL DEFAULT 3,
    reset_token TEXT,
    reset_token_used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    text TEXT,
    rating INTEGER
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

DROP = """
DROP TABLE IF EXISTS feedback;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS meta;
"""


def hash_password(password: str) -> str:
    """Deterministic test-only password hash."""
    return hashlib.sha256((PASSWORD_SALT + password).encode("utf-8")).hexdigest()


def connect(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def _seed(conn: sqlite3.Connection, cache_epoch: int = 1) -> None:
    for user in SEED_USERS:
        conn.execute(
            """
            INSERT INTO users
                (id, username, email, password_hash, role, display_name, bio,
                 credits, ai_uses, ai_quota, reset_token, reset_token_used)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 0)
            """,
            (
                user["id"],
                user["username"],
                user["email"],
                hash_password(user["password"]),
                user["role"],
                user["display_name"],
                user["bio"],
                user["credits"],
                user["ai_uses"],
                user["ai_quota"],
            ),
        )
    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('cache_epoch', ?)",
        (str(cache_epoch),),
    )
    conn.commit()


def init_db(db_path: str | Path) -> None:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            _seed(conn)
        else:
            conn.commit()
    finally:
        conn.close()


def reset_db(db_path: str | Path) -> None:
    """Drop and recreate every table, then load the deterministic seed.

    The cache epoch is advanced so in-process dashboard entries from before the
    reset can never be served after it, even without an explicit cache clear.
    """
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    try:
        try:
            row = conn.execute(
                "SELECT value FROM meta WHERE key = 'cache_epoch'"
            ).fetchone()
            previous_epoch = int(row["value"]) if row else 0
        except (sqlite3.Error, ValueError):
            previous_epoch = 0
        conn.executescript(DROP)
        conn.executescript(SCHEMA)
        _seed(conn, cache_epoch=previous_epoch + 1)
        conn.commit()
    finally:
        conn.close()


def get_user(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_user_by_email(conn: sqlite3.Connection, email: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def list_users(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM users ORDER BY id").fetchall()


def cache_epoch(db_path: str | Path) -> int:
    conn = connect(db_path)
    try:
        row = conn.execute("SELECT value FROM meta WHERE key = 'cache_epoch'").fetchone()
        return int(row["value"]) if row else 0
    finally:
        conn.close()


def row_to_public(row: sqlite3.Row) -> dict:
    """Serialize a user row without the password hash.

    The vulnerable table endpoint intentionally includes reset tokens; the
    serializer only removes the password hash because that would make login
    impossible to demonstrate.
    """
    data = dict(row)
    data.pop("password_hash", None)
    return data
