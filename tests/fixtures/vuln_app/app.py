"""Standard-library HTTP app for the T8 vulnerable fixture.

Every weakness here is intentional and documented in SEEDED.md. The server
binds to 127.0.0.1 only and performs no outbound network access; the SSRF
proof maps ``*.nip.io`` to the fixture's own loopback address, which is what
public nip.io DNS does, so the result is deterministic offline.
"""

from __future__ import annotations

import html
import json
import re
import secrets
import threading
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

from . import storage

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------

_CACHE: dict[tuple[str, int], bytes] = {}
_CACHE_LOCK = threading.Lock()

_SPEND_GATES: dict[int, threading.Barrier] = {}
_SPEND_GATE_LOCK = threading.Lock()


def clear_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()


class _NoRedirectHandler(HTTPRedirectHandler):
    """Refuse every redirect hop so a fetch cannot leave the fixture listener."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_bind_host(host: str) -> None:
    """The fixture is a loopback-only authorized target."""
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError(
            f"fixture binds loopback only (127.0.0.1 or localhost); refused {host!r}"
        )


class FixtureHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, db_path):
        self.db_path = str(db_path)
        super().__init__(address, handler)


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    server_version = "SAKFixture/1.0"
    protocol_version = "HTTP/1.1"

    # Keep pytest output clean; the fixture is not a real server.
    def log_message(self, fmt, *args):  # noqa: A003 - stdlib signature
        return

    # -- response helpers -------------------------------------------------

    def _send(self, status, body=b"", content_type="text/plain; charset=utf-8", headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, status, payload, headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8", headers)

    def _html(self, status, markup, headers=None):
        self._send(status, markup.encode("utf-8"), "text/html; charset=utf-8", headers)

    def _redirect(self, location, status=302):
        self.send_response(status)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    # -- request helpers --------------------------------------------------

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if content_type == "application/json":
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return {}
            return parsed if isinstance(parsed, dict) else {}
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return {}
        parsed_form = parse_qs(text, keep_blank_values=True)
        return {key: values[0] if len(values) == 1 else values for key, values in parsed_form.items()}

    def _current_user(self):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        cookies = SimpleCookie()
        try:
            cookies.load(raw)
        except Exception:
            return None
        if "sid" not in cookies:
            return None
        sid = cookies["sid"].value
        conn = storage.connect(self.server.db_path)
        try:
            row = conn.execute(
                "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.sid = ?",
                (sid,),
            ).fetchone()
        finally:
            conn.close()
        return row

    def _require_user(self):
        user = self._current_user()
        if user is None:
            self._json(401, {"error": "authentication required"})
            return None
        return user

    def _set_session(self, user_id):
        sid = secrets.token_hex(16)
        conn = storage.connect(self.server.db_path)
        try:
            conn.execute("INSERT INTO sessions (sid, user_id) VALUES (?, ?)", (sid, user_id))
            conn.commit()
        finally:
            conn.close()
        self._pending_session = sid
        return sid

    def _send_headers_extra(self):
        sid = getattr(self, "_pending_session", None)
        return {"Set-Cookie": f"sid={sid}; Path=/; HttpOnly; SameSite=Lax"} if sid else None

    def _user_json(self, row):
        return storage.row_to_public(row)

    # -- dispatch ---------------------------------------------------------

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PATCH(self):
        self._dispatch("PATCH")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _dispatch(self, method):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query, keep_blank_values=True)
        try:
            self._route(method, path, query)
        except BrokenPipeError:
            return
        except Exception as exc:  # fixture: surface deterministic errors as JSON
            self._json(500, {"error": "fixture_error", "detail": str(exc)})

    def _route(self, method, path, query):
        # UI / unauthenticated surfaces
        if path == "/" and method == "GET":
            return self._index()
        if path == "/login" and method == "GET":
            return self._login_form()
        if path == "/login" and method == "POST":
            return self._login(query)
        if path == "/logout" and method == "GET":
            return self._logout()
        if path == "/profile" and method == "GET":
            return self._profile_page(escape=False)
        if path == "/profile/safe" and method == "GET":
            return self._profile_page(escape=True)
        if path == "/public/status" and method == "GET":
            return self._json(200, {"status": "ok", "fixture": "sak-t8"})
        if path == "/internal/metadata" and method == "GET":
            return self._json(
                200,
                {
                    "service": "fixture-metadata",
                    "token": "INTERNAL-ONLY-TOKEN=t8-metadata-fixture",
                },
            )

        # Session-scoped account API
        if path == "/api/me" and method == "GET":
            return self._api_me()
        if path == "/api/me" and method == "PATCH":
            return self._api_me_patch()
        if path == "/api/profile" and method == "GET":
            return self._api_profile()
        if path == "/api/profile" and method == "PATCH":
            return self._api_profile_patch()

        match = re.fullmatch(r"/api/users/(\d+)/safe", path)
        if match:
            return self._api_user_safe(method, int(match.group(1)))
        match = re.fullmatch(r"/api/users/(\d+)", path)
        if match:
            return self._api_user(method, int(match.group(1)))

        if path == "/api/table/users" and method == "GET":
            return self._api_table_users(vulnerable=True)
        if path == "/api/table/users/safe" and method == "GET":
            return self._api_table_users(vulnerable=False)

        if path == "/api/password-reset/request" and method == "POST":
            return self._api_password_reset_request()
        if path == "/api/password-reset/confirm" and method == "POST":
            return self._api_password_reset_confirm()

        if path == "/api/feedback" and method == "GET":
            return self._api_feedback_list()
        if path == "/api/feedback" and method == "POST":
            return self._api_feedback_create(vulnerable=True)
        if path == "/api/feedback/safe" and method == "POST":
            return self._api_feedback_create(vulnerable=False)

        if path == "/admin/hidden/purge-cache" and method == "POST":
            return self._admin_hidden_purge()
        if path == "/admin/action" and method == "POST":
            return self._admin_action()

        if path == "/ai" and method == "GET":
            return self._ai_page()
        if path == "/api/ai/complete" and method == "POST":
            return self._api_ai_complete(vulnerable=True)
        if path == "/api/ai/complete/safe" and method == "POST":
            return self._api_ai_complete(vulnerable=False)

        if path == "/api/credits/spend" and method == "POST":
            return self._api_credits_spend(vulnerable=True)
        if path == "/api/credits/spend/safe" and method == "POST":
            return self._api_credits_spend(vulnerable=False)

        if path == "/api/fetch" and method == "POST":
            return self._api_fetch(vulnerable=True)
        if path == "/api/fetch/safe" and method == "POST":
            return self._api_fetch(vulnerable=False)

        if path == "/dashboard" and method == "GET":
            return self._dashboard(vulnerable=True)
        if path == "/dashboard/safe" and method == "GET":
            return self._dashboard(vulnerable=False)

        if path == "/go" and method == "GET":
            return self._go(query, safe=False)
        if path == "/go/safe" and method == "GET":
            return self._go(query, safe=True)

        match = re.fullmatch(r"/preview/safe/(\d+)", path)
        if match and method == "GET":
            return self._preview(int(match.group(1)), safe=True)
        match = re.fullmatch(r"/preview/(\d+)", path)
        if match and method == "GET":
            return self._preview(int(match.group(1)), safe=False)

        if path == "/api/chat" and method == "POST":
            return self._api_chat(vulnerable=True)
        if path == "/api/chat/safe" and method == "POST":
            return self._api_chat(vulnerable=False)

        return self._json(404, {"error": "not found", "path": path})

    # -- UI ---------------------------------------------------------------

    def _index(self):
        self._html(
            200,
            """<!doctype html><html><body>
<h1>SAK local fixture</h1>
<p>Evaluator-only intentionally vulnerable target.</p>
<ul>
<li><a href="/login">Login</a></li>
<li><a href="/api/table/users">Public user table</a></li>
<li><a href="/preview/1">Preview account 1</a></li>
</ul>
</body></html>""",
        )

    def _login_form(self):
        self._html(
            200,
            """<!doctype html><html><body>
<h1>Login</h1>
<form method="post" action="/login">
<input name="username" value="alice"><input name="password" type="password" value="alice-pw">
<button type="submit">Sign in</button>
</form></body></html>""",
        )

    def _login(self, query):
        body = self._read_body()
        username = str(body.get("username", ""))
        password = str(body.get("password", ""))
        conn = storage.connect(self.server.db_path)
        try:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ? OR email = ?",
                (username, username),
            ).fetchone()
        finally:
            conn.close()
        if row is None or row["password_hash"] != storage.hash_password(password):
            return self._json(401, {"error": "invalid credentials"})
        self._set_session(row["id"])
        target = body.get("next") or (query.get("next") or [None])[0]
        headers = self._send_headers_extra()
        if target:
            # Deliberate open redirect: next is used verbatim.
            self.send_response(302)
            self.send_header("Location", str(target))
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.send_header("Content-Length", "0")
            self.end_headers()
            self._pending_session = None
            return
        self.send_response(302)
        self.send_header("Location", "/profile")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", "0")
        self.end_headers()
        self._pending_session = None

    def _logout(self):
        raw = self.headers.get("Cookie")
        if raw:
            cookies = SimpleCookie()
            try:
                cookies.load(raw)
            except Exception:
                cookies = None
            if cookies and "sid" in cookies:
                conn = storage.connect(self.server.db_path)
                try:
                    conn.execute("DELETE FROM sessions WHERE sid = ?", (cookies["sid"].value,))
                    conn.commit()
                finally:
                    conn.close()
        self._redirect("/login")

    def _profile_page(self, escape):
        user = self._require_user()
        if user is None:
            return
        name = user["display_name"] or ""
        rendered_name = html.escape(name, quote=True) if escape else name
        rendered_email = html.escape(user["email"], quote=True)
        mode = "safe" if escape else "vulnerable"
        # Stored XSS: the vulnerable page interpolates the profile name raw.
        self._html(
            200,
            f"""<!doctype html><html><body>
<h1>Profile ({mode})</h1>
<p>Email: {rendered_email}</p>
<div id="display-name">{rendered_name}</div>
<p>Role: {html.escape(user['role'])}</p>
</body></html>""",
        )

    def _ai_page(self):
        user = self._require_user()
        if user is None:
            return
        remaining = max(0, int(user["ai_quota"]) - int(user["ai_uses"]))
        self._html(
            200,
            f"""<!doctype html><html><body>
<h1>AI assistant</h1>
<p id="quota">Quota: {user['ai_quota']} used: {user['ai_uses']} remaining: {remaining}</p>
<form method="post" action="/api/ai/complete">
<input name="prompt"><button type="submit">Ask</button>
</form></body></html>""",
        )

    # -- account API ------------------------------------------------------

    def _api_me(self):
        user = self._require_user()
        if user is None:
            return
        self._json(200, self._user_json(user))

    def _api_me_patch(self):
        """Safe self-service update: only display_name and bio; role is ignored."""
        user = self._require_user()
        if user is None:
            return
        body = self._read_body()
        name = body.get("display_name", user["display_name"])
        bio = body.get("bio", user["bio"])
        if not isinstance(name, str) or not (1 <= len(name) <= 80):
            return self._json(400, {"error": "display_name must be 1..80 characters"})
        conn = storage.connect(self.server.db_path)
        try:
            conn.execute(
                "UPDATE users SET display_name = ?, bio = ? WHERE id = ?",
                (name, str(bio), user["id"]),
            )
            conn.commit()
            updated = storage.get_user(conn, user["id"])
        finally:
            conn.close()
        self._json(200, self._user_json(updated))

    def _api_profile(self):
        user = self._require_user()
        if user is None:
            return
        self._json(200, self._user_json(user))

    def _api_profile_patch(self):
        """Vulnerable mass assignment: every submitted column is trusted."""
        user = self._require_user()
        if user is None:
            return
        body = self._read_body()
        editable = ("email", "display_name", "bio", "role", "credits", "ai_uses", "ai_quota")
        assignments = []
        values = []
        for field in editable:
            if field in body:
                assignments.append(f"{field} = ?")
                values.append(body[field])
        if assignments:
            values.append(user["id"])
            conn = storage.connect(self.server.db_path)
            try:
                conn.execute(f"UPDATE users SET {', '.join(assignments)} WHERE id = ?", values)
                conn.commit()
                updated = storage.get_user(conn, user["id"])
            finally:
                conn.close()
        else:
            updated = user
        self._json(200, self._user_json(updated))

    def _api_user(self, method, user_id):
        user = self._require_user()
        if user is None:
            return
        conn = storage.connect(self.server.db_path)
        try:
            target = storage.get_user(conn, user_id)
            if target is None:
                return self._json(404, {"error": "user not found"})
            if method == "GET":
                # IDOR: no ownership check.
                return self._json(200, self._user_json(target))
            if method == "PATCH":
                body = self._read_body()
                editable = ("email", "display_name", "bio", "role", "credits", "ai_uses", "ai_quota")
                assignments = []
                values = []
                for field in editable:
                    if field in body:
                        assignments.append(f"{field} = ?")
                        values.append(body[field])
                if assignments:
                    values.append(user_id)
                    conn.execute(f"UPDATE users SET {', '.join(assignments)} WHERE id = ?", values)
                    conn.commit()
                updated = storage.get_user(conn, user_id)
                return self._json(200, self._user_json(updated))
            if method == "DELETE":
                # IDOR: any authenticated account can delete any other account.
                conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
                conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
                conn.commit()
                return self._send(204, b"", "application/json", None)
            return self._json(405, {"error": "method not allowed"})
        finally:
            conn.close()

    def _api_user_safe(self, method, user_id):
        user = self._require_user()
        if user is None:
            return
        if user_id != user["id"] and user["role"] != "admin":
            return self._json(403, {"error": "forbidden: not the account owner"})
        conn = storage.connect(self.server.db_path)
        try:
            target = storage.get_user(conn, user_id)
            if target is None:
                return self._json(404, {"error": "user not found"})
            if method == "GET":
                return self._json(200, self._user_json(target))
            if method == "PATCH":
                body = self._read_body()
                name = body.get("display_name", target["display_name"])
                if not isinstance(name, str) or not (1 <= len(name) <= 80):
                    return self._json(400, {"error": "display_name must be 1..80 characters"})
                # Role and credits are intentionally ignored.
                conn.execute(
                    "UPDATE users SET display_name = ? WHERE id = ?",
                    (name, user_id),
                )
                conn.commit()
                updated = storage.get_user(conn, user_id)
                return self._json(200, self._user_json(updated))
            return self._json(405, {"error": "method not allowed"})
        finally:
            conn.close()

    def _api_table_users(self, vulnerable):
        if not vulnerable:
            user = self._require_user()
            if user is None:
                return
            if user["role"] != "admin":
                return self._json(403, {"error": "admin only"})
        conn = storage.connect(self.server.db_path)
        try:
            rows = storage.list_users(conn)
            payload = [self._user_json(row) for row in rows]
        finally:
            conn.close()
        self._json(200, payload)

    # -- password reset ---------------------------------------------------

    def _api_password_reset_request(self):
        body = self._read_body()
        email = str(body.get("email", ""))
        conn = storage.connect(self.server.db_path)
        try:
            user = storage.get_user_by_email(conn, email)
            if user is None:
                return self._json(404, {"error": "unknown email"})
            token = secrets.token_urlsafe(12)
            conn.execute(
                "UPDATE users SET reset_token = ?, reset_token_used = 0 WHERE id = ?",
                (token, user["id"]),
            )
            conn.commit()
        finally:
            conn.close()
        # The token is returned to the caller and never invalidated on use.
        self._json(200, {"status": "sent", "token": token})

    def _api_password_reset_confirm(self):
        body = self._read_body()
        token = str(body.get("token", ""))
        new_password = str(body.get("new_password", ""))
        conn = storage.connect(self.server.db_path)
        try:
            user = conn.execute(
                "SELECT * FROM users WHERE reset_token = ?", (token,)
            ).fetchone()
            if user is None:
                return self._json(400, {"error": "invalid token"})
            # Reusable tokens: reset_token_used is never enforced or cleared.
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (storage.hash_password(new_password), user["id"]),
            )
            conn.commit()
        finally:
            conn.close()
        self._json(200, {"status": "password changed", "username": user["username"]})

    # -- feedback / hostile values ---------------------------------------

    def _api_feedback_list(self):
        user = self._require_user()
        if user is None:
            return
        conn = storage.connect(self.server.db_path)
        try:
            rows = conn.execute(
                "SELECT id, user_id, text, rating FROM feedback ORDER BY id"
            ).fetchall()
        finally:
            conn.close()
        self._json(200, [dict(row) for row in rows])

    def _api_feedback_create(self, vulnerable):
        user = self._require_user()
        if user is None:
            return
        body = self._read_body()
        text = body.get("text")
        rating = body.get("rating")
        if not vulnerable:
            if not isinstance(text, str) or not (1 <= len(text) <= 500):
                return self._json(400, {"error": "text must be 1..500 characters"})
            try:
                rating_int = int(rating)
            except (TypeError, ValueError):
                return self._json(400, {"error": "rating must be an integer"})
            if not (1 <= rating_int <= 5):
                return self._json(400, {"error": "rating must be 1..5"})
            rating = rating_int
        conn = storage.connect(self.server.db_path)
        try:
            conn.execute(
                "INSERT INTO feedback (user_id, text, rating) VALUES (?, ?, ?)",
                (user["id"], text, rating),
            )
            conn.commit()
            row = conn.execute("SELECT last_insert_rowid() AS id").fetchone()
            stored = conn.execute(
                "SELECT id, user_id, text, rating FROM feedback WHERE id = ?",
                (row["id"],),
            ).fetchone()
        finally:
            conn.close()
        self._json(200, dict(stored))

    # -- admin ------------------------------------------------------------

    def _admin_hidden_purge(self):
        # Hidden in the UI only; the route has no authorization check.
        clear_cache()
        self._json(200, {"purged": True, "action": "purge-cache"})

    def _admin_action(self):
        user = self._require_user()
        if user is None:
            return
        if user["role"] != "admin":
            return self._json(403, {"error": "admin only"})
        self._json(200, {"ok": True, "action": "admin-action"})

    # -- AI quota ---------------------------------------------------------

    def _api_ai_complete(self, vulnerable):
        user = self._require_user()
        if user is None:
            return
        body = self._read_body()
        prompt = str(body.get("prompt", ""))
        conn = storage.connect(self.server.db_path)
        try:
            fresh = storage.get_user(conn, user["id"])
            if not vulnerable and int(fresh["ai_uses"]) >= int(fresh["ai_quota"]):
                return self._json(
                    429,
                    {
                        "error": "AI quota exhausted",
                        "used": fresh["ai_uses"],
                        "quota": fresh["ai_quota"],
                    },
                )
            conn.execute(
                "UPDATE users SET ai_uses = ai_uses + 1 WHERE id = ?",
                (user["id"],),
            )
            conn.commit()
            used = conn.execute(
                "SELECT ai_uses, ai_quota FROM users WHERE id = ?", (user["id"],)
            ).fetchone()
        finally:
            conn.close()
        # The vulnerable endpoint never enforces the quota.
        self._json(
            200,
            {
                "answer": f"fixture answer for: {prompt[:40]}",
                "used": used["ai_uses"],
                "quota": used["ai_quota"],
            },
        )

    # -- credits ----------------------------------------------------------

    def _api_credits_spend(self, vulnerable):
        user = self._require_user()
        if user is None:
            return
        body = self._read_body()
        try:
            amount = int(body.get("amount", 0))
        except (TypeError, ValueError):
            return self._json(400, {"error": "amount must be an integer"})
        if amount <= 0:
            return self._json(400, {"error": "amount must be positive"})

        if vulnerable:
            # Read-then-write across two connections with a rendezvous window,
            # so concurrent requests both pass the (missing) balance check.
            conn = storage.connect(self.server.db_path)
            try:
                before = storage.get_user(conn, user["id"])
            finally:
                conn.close()
            if before is None:
                return self._json(404, {"error": "user not found"})
            # Non-atomic check: it happens before the rendezvous window, so two
            # concurrent requests both see the pre-debit balance.
            if int(before["credits"]) < amount:
                return self._json(
                    400,
                    {"error": "insufficient credits", "credits": before["credits"]},
                )
            gate = _spend_gate(user["id"])
            try:
                gate.wait(timeout=2.0)
            except threading.BrokenBarrierError:
                pass
            finally:
                with _SPEND_GATE_LOCK:
                    if _SPEND_GATES.get(user["id"]) is gate:
                        _SPEND_GATES.pop(user["id"], None)
            conn = storage.connect(self.server.db_path)
            try:
                conn.execute(
                    "UPDATE users SET credits = credits - ? WHERE id = ?",
                    (amount, user["id"]),
                )
                conn.commit()
                after = storage.get_user(conn, user["id"])
            finally:
                conn.close()
            return self._json(
                200,
                {
                    "spent": amount,
                    "credits": after["credits"],
                    "note": "balance was not checked atomically",
                },
            )

        # Safe path: serialize the check and debit in one immediate transaction.
        conn = storage.connect(self.server.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            current = storage.get_user(conn, user["id"])
            if current is None:
                conn.rollback()
                return self._json(404, {"error": "user not found"})
            if int(current["credits"]) < amount:
                conn.rollback()
                return self._json(
                    400,
                    {"error": "insufficient credits", "credits": current["credits"]},
                )
            conn.execute(
                "UPDATE users SET credits = credits - ? WHERE id = ?",
                (amount, user["id"]),
            )
            conn.commit()
            after = storage.get_user(conn, user["id"])
        finally:
            conn.close()
        self._json(200, {"spent": amount, "credits": after["credits"]})

    # -- SSRF -------------------------------------------------------------

    def _api_fetch(self, vulnerable):
        user = self._require_user()
        if user is None:
            return
        body = self._read_body()
        target = str(body.get("url", ""))
        parsed = urlparse(target)

        if not vulnerable:
            # Strict allowlist: only the fixture's own public status endpoint.
            port = self.server.server_address[1]
            allowed_prefixes = (f"http://127.0.0.1:{port}/public/",)
            if not any(target.startswith(prefix) for prefix in allowed_prefixes):
                return self._json(403, {"error": "URL not allowlisted"})
        else:
            blocked = ("localhost", "127.0.0.1", "169.254.169.254", "::1")
            if any(item in target for item in blocked):
                return self._json(400, {"error": "blocked destination"})
            host = parsed.hostname or ""
            if not host.endswith(".nip.io"):
                return self._json(400, {"error": "unsupported destination"})
            # Deterministic offline stand-in for nip.io DNS: any *.nip.io host
            # resolves to the fixture's loopback listener.
            port = self.server.server_address[1]
            target = f"http://127.0.0.1:{port}{parsed.path or '/'}"
            if parsed.query:
                target += "?" + parsed.query

        try:
            # Explicit empty proxy map plus no-redirect handler: the fixture
            # must never leave its own loopback listener.
            opener = build_opener(ProxyHandler({}), _NoRedirectHandler())
            with opener.open(target, timeout=3) as response:  # noqa: S310 - fixture only
                body_text = response.read().decode("utf-8", "replace")
                status = response.status
        except Exception as exc:
            return self._json(502, {"error": "fetch failed", "detail": str(exc)})
        self._json(200, {"status": status, "body": body_text, "fetched": target})

    # -- cache ------------------------------------------------------------

    def _dashboard(self, vulnerable):
        user = self._require_user()
        if user is None:
            return
        body = json.dumps(
            {
                "username": user["username"],
                "email": user["email"],
                "credits": user["credits"],
                "display_name": user["display_name"],
            },
            ensure_ascii=False,
        ).encode("utf-8")
        if not vulnerable:
            # Per-user, non-cacheable response.
            return self._send(
                200,
                body,
                "application/json; charset=utf-8",
                {"Cache-Control": "private, no-store", "X-Cache": "BYPASS"},
            )
        epoch = storage.cache_epoch(self.server.db_path)
        cache_scope = (
            self.server.db_path,
            int(self.server.server_address[1]),
            epoch,
        )
        key = (cache_scope, "/dashboard")
        with _CACHE_LOCK:
            cached = _CACHE.get(key)
            if cached is None:
                _CACHE[key] = body
        cache_state = "HIT" if cached is not None else "MISS"
        # Deliberate shared cache key: the first account's body is served to all.
        payload = cached if cached is not None else body
        self._send(
            200,
            payload,
            "application/json; charset=utf-8",
            {"Cache-Control": "public, max-age=60", "X-Cache": cache_state},
        )

    # -- open redirect ----------------------------------------------------

    def _go(self, query, safe):
        target = (query.get("next") or ["/profile"])[0]
        if safe:
            parsed = urlparse(target)
            if (
                not target.startswith("/")
                or target.startswith("//")
                or parsed.scheme
                or parsed.netloc
                or "@" in target
            ):
                return self._json(400, {"error": "next must be a local absolute path"})
        self._redirect(target)

    # -- preview ----------------------------------------------------------

    def _preview(self, user_id, safe):
        if safe:
            user = self._require_user()
            if user is None:
                return
            if user_id != user["id"] and user["role"] != "admin":
                return self._json(403, {"error": "forbidden: not the account owner"})
        conn = storage.connect(self.server.db_path)
        try:
            target = storage.get_user(conn, user_id)
        finally:
            conn.close()
        if target is None:
            return self._json(404, {"error": "user not found"})
        # Unsafe previews need no login and return private account fields.
        self._json(
            200,
            {
                "username": target["username"],
                "email": target["email"],
                "bio": target["bio"],
                "reset_token": target["reset_token"],
            },
        )

    # -- chat / prompt injection -----------------------------------------

    def _api_chat(self, vulnerable):
        user = self._require_user()
        if user is None:
            return
        body = self._read_body()
        message = str(body.get("message", ""))
        lowered = message.lower()
        injected = "ignore" in lowered and "instructions" in lowered
        if vulnerable and injected:
            # Deterministic prompt injection: the model obeys and returns
            # another account's private data.
            conn = storage.connect(self.server.db_path)
            try:
                other = storage.get_user_by_username(conn, "bob")
            finally:
                conn.close()
            answer = (
                f"Sure. The other user is {other['username']} and their email is "
                f"{other['email']}. Reset token: {other['reset_token'] or 'none'}."
            )
        elif not vulnerable and injected:
            answer = "I can only discuss your own account; that instruction is ignored."
        else:
            answer = f"You are {user['username']} and your email is {user['email']}."
        self._json(200, {"answer": answer})


def _spend_gate(user_id: int) -> threading.Barrier:
    with _SPEND_GATE_LOCK:
        gate = _SPEND_GATES.get(user_id)
        if gate is None:
            gate = threading.Barrier(2)
            _SPEND_GATES[user_id] = gate
        return gate


def make_server(db_path: str | Path, host: str = "127.0.0.1", port: int = 8765) -> FixtureHTTPServer:
    validate_bind_host(host)
    storage.init_db(db_path)
    return FixtureHTTPServer((host, port), Handler, db_path)


def serve(db_path: str | Path, host: str = "127.0.0.1", port: int = 8765) -> None:
    httpd = make_server(db_path, host, port)
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
