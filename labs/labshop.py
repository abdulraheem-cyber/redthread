from __future__ import annotations

import argparse
import json
import re
import secrets
import sqlite3
import threading
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

USERS = {
    "alice": "alice-pw",
    "bob": "bob-pw",
}

ORDERS = {
    101: {"id": 101, "owner": "alice", "item": "Mechanical keyboard", "total": 129.0},
    102: {"id": 102, "owner": "bob", "item": "USB-C dock", "total": 89.5},
}

PRODUCTS = [
    ("Notebook", 6.5),
    ("Desk lamp", 24.0),
    ("Mechanical keyboard", 129.0),
]


class LabState:
    def __init__(self) -> None:
        self.sessions: dict[str, str] = {}
        self.lock = threading.Lock()

    def sign_in(self, user: str) -> str:
        token = secrets.token_hex(16)
        with self.lock:
            self.sessions[token] = user
        return token

    def user_for(self, token: str) -> str | None:
        with self.lock:
            return self.sessions.get(token)

    def sign_out(self, token: str) -> None:
        with self.lock:
            self.sessions.pop(token, None)


def _page(title: str, body: str, user: str | None = None) -> str:
    nav = " / ".join(
        [
            '<a href="/">home</a>',
            '<a href="/products?category=books">products</a>',
            '<a href="/search?q=books">search</a>',
            '<a href="/redirect?next=/account">redirect</a>',
            '<a href="/account">account</a>',
            '<a href="/login">login</a>',
            '<a href="/api/config">api</a>',
            '<a href="/graphql">graphql</a>',
        ]
    )
    who = f'<span class="who">Signed in as {escape(user)}</span>' if user else ""
    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        f"<title>{escape(title)} - LabShop</title></head><body>"
        f"<header><strong>LabShop</strong> {who}<nav>{nav}</nav></header>"
        f"<main><h1>{escape(title)}</h1>{body}</main>"
        "<footer>LabShop is a deliberately vulnerable test application.</footer>"
        "</body></html>"
    )


class LabHandler(BaseHTTPRequestHandler):
    server: LabServer

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send(
        self,
        status: int,
        body: str | bytes,
        content_type: str = "text/html; charset=utf-8",
        headers: dict[str, str] | None = None,
    ) -> None:
        raw = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Powered-By", "LabShop/0.1")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def _redirect(self, location: str, status: int = 302) -> None:
        self.send_response(status)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _session_user(self) -> tuple[str | None, str | None]:
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            name, separator, value = part.strip().partition("=")
            if separator and name == "sid":
                return self.server.state.user_for(value), value
        return None, None

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        path = parts.path or "/"
        query = parse_qs(parts.query, keep_blank_values=True)

        if path == "/":
            body = "<p>Your account, orders and the status API live here.</p>"
            self._send(HTTPStatus.OK, _page("Welcome", body, self._session_user()[0]))
        elif path == "/products":
            category = query.get("category", ["all"])[0]
            rows = "".join(f"<li>{escape(name)} - ${price:.2f}</li>" for name, price in PRODUCTS)
            body = f"<p>Category: {category}</p><ul>{rows}</ul>"
            self._send(HTTPStatus.OK, _page("Products", body, self._session_user()[0]))
        elif path == "/search":
            self._search(query.get("q", [""])[0])
        elif path == "/redirect":
            target = query.get("next", ["/"])[0]
            if target.startswith(("http://", "https://", "//")):
                self._redirect(target)
            elif target.startswith("/"):
                self._redirect(target)
            else:
                self._send(
                    HTTPStatus.BAD_REQUEST,
                    _page("Bad redirect", "<p>Relative path expected.</p>"),
                )
        elif path == "/api/config":
            origin = self.headers.get("Origin")
            headers = {}
            if origin:
                headers["Access-Control-Allow-Origin"] = origin
                headers["Access-Control-Allow-Credentials"] = "true"
                headers["Vary"] = "Origin"
            payload = {
                "environment": "lab",
                "registration": True,
                "support_email": "help@labshop.test",
            }
            self._send(HTTPStatus.OK, json.dumps(payload), "application/json", headers)
        elif path == "/login":
            self._send(HTTPStatus.OK, _login_page())
        elif path == "/logout":
            _, token = self._session_user()
            if token:
                self.server.state.sign_out(token)
            self._send(
                HTTPStatus.OK,
                _page("Signed out", "<p>Goodbye.</p>"),
                headers={"Set-Cookie": "sid=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"},
            )
        elif path == "/account":
            user, _ = self._session_user()
            if not user:
                self._redirect("/login")
                return
            self._account(user)
        elif match := re.fullmatch(r"/api/orders/(\d+)", path):
            self._order(int(match.group(1)))
        elif path == "/graphql":
            self._send(
                HTTPStatus.METHOD_NOT_ALLOWED,
                json.dumps({"error": "POST a GraphQL query"}),
                "application/json",
            )
        else:
            self._send(HTTPStatus.NOT_FOUND, _page("Not found", "<p>No route.</p>"))

    def do_POST(self) -> None:
        parts = urlsplit(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b""
        if parts.path == "/login":
            self._login(raw.decode("utf-8", errors="replace"))
        elif parts.path == "/graphql":
            self._graphql(raw)
        else:
            self._send(HTTPStatus.NOT_FOUND, _page("Not found", "<p>No route.</p>"))

    def _search(self, value: str) -> None:
        connection = sqlite3.connect(":memory:")
        try:
            connection.execute("CREATE TABLE products (name TEXT, price REAL)")
            connection.executemany("INSERT INTO products VALUES (?, ?)", PRODUCTS)
            sql = f"SELECT name, price FROM products WHERE name LIKE '%{value}%' ORDER BY name"
            try:
                rows = connection.execute(sql).fetchall()
            except sqlite3.Error as exc:
                body = (
                    '<p class="error">Search failed: '
                    f"sqlite3.{type(exc).__name__}: {escape(str(exc))}</p>"
                )
                self._send(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    _page("Search error", body, self._session_user()[0]),
                )
                return
            items = "".join(
                f"<li>{escape(str(name))} - ${float(price):.2f}</li>" for name, price in rows
            )
            body = f"<p>Results for {escape(value)}</p><ul>{items}</ul>"
            self._send(HTTPStatus.OK, _page("Search", body, self._session_user()[0]))
        finally:
            connection.close()

    def _login(self, body: str) -> None:
        form = parse_qs(body, keep_blank_values=True)
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]
        if USERS.get(username) != password:
            self._send(
                HTTPStatus.UNAUTHORIZED,
                _login_page("Invalid username or password."),
            )
            return
        token = self.server.state.sign_in(username)
        self._send(
            HTTPStatus.SEE_OTHER,
            _page("Signed in", "<p>Login complete.</p>", username),
            headers={
                "Location": "/account",
                "Set-Cookie": f"sid={token}; Path=/; HttpOnly; SameSite=Lax",
            },
        )

    def _account(self, user: str) -> None:
        own = [order for order in ORDERS.values() if order["owner"] == user]
        links = "".join(
            f'<li><a href="/api/orders/{order["id"]}">Order {order["id"]}</a>'
            f" - {escape(order['item'])}</li>"
            for order in own
        )
        body = f"<p>Signed in as {escape(user)}</p><h2>Your orders</h2><ul>{links}</ul>"
        self._send(HTTPStatus.OK, _page("Account", body, user))

    def _order(self, order_id: int) -> None:
        user, _ = self._session_user()
        if not user:
            self._send(
                HTTPStatus.UNAUTHORIZED,
                json.dumps({"error": "authentication required"}),
                "application/json",
            )
            return
        order = ORDERS.get(order_id)
        if order is None:
            self._send(
                HTTPStatus.NOT_FOUND,
                json.dumps({"error": "order not found"}),
                "application/json",
            )
            return
        self._send(HTTPStatus.OK, json.dumps(order), "application/json")

    def _graphql(self, raw: bytes) -> None:
        try:
            payload = json.loads(raw.decode("utf-8"))
            query = str(payload.get("query", ""))
        except (ValueError, UnicodeDecodeError):
            self._send(
                HTTPStatus.BAD_REQUEST,
                json.dumps({"errors": [{"message": "request body must be JSON"}]}),
                "application/json",
            )
            return
        if "__schema" not in query:
            self._send(
                HTTPStatus.OK,
                json.dumps({"data": {"__typename": "Query"}}),
                "application/json",
            )
            return
        schema = {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [
                {
                    "name": "Query",
                    "kind": "OBJECT",
                    "fields": [{"name": "product"}, {"name": "order"}],
                },
                {
                    "name": "Mutation",
                    "kind": "OBJECT",
                    "fields": [{"name": "signIn"}],
                },
                {"name": "String", "kind": "SCALAR", "fields": None},
            ],
        }
        self._send(
            HTTPStatus.OK,
            json.dumps({"data": {"__schema": schema}}),
            "application/json",
        )


def _login_page(error: str = "") -> str:
    notice = f'<p class="error">{escape(error)}</p>' if error else ""
    return _page(
        "Sign in",
        notice + '<form method="post" action="/login">'
        '<label>Username <input type="text" name="username"></label>'
        '<label>Password <input type="password" name="password"></label>'
        '<button type="submit" name="submit" value="login">Sign in</button>'
        "</form>",
    )


class LabServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, host: str = "127.0.0.1", port: int = 8000):
        super().__init__((host, port), LabHandler)
        self.state = LabState()
        bound_host, bound_port = self.server_address[:2]
        self.base_url = f"http://{bound_host}:{bound_port}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the vulnerable LabShop demo target.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    server = LabServer(args.host, args.port)
    print(f"labshop listening on {server.base_url}")
    print("accounts: alice/alice-pw and bob/bob-pw")
    print("Ctrl+C to stop")
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
