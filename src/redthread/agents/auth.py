from __future__ import annotations

import base64
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin

from redthread.audit import AuditLog
from redthread.config import Config, IdentitySettings
from redthread.graph import Graph
from redthread.http import HttpSession
from redthread.models import utcnow


@dataclass
class FormField:
    name: str
    value: str = ""
    kind: str = "text"


@dataclass
class Form:
    action: str = ""
    method: str = "GET"
    fields: list[FormField] = field(default_factory=list)

    def has_password(self) -> bool:
        return any(field.kind == "password" for field in self.fields)

    def named(self) -> dict[str, str]:
        return {field.name: field.value for field in self.fields if field.name}


class FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[Form] = []
        self._current: Form | None = None
        self._textarea: FormField | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): (value or "") for key, value in attrs}
        if tag.lower() == "form":
            self._current = Form(
                action=values.get("action", ""),
                method=values.get("method", "GET").upper(),
            )
            self.forms.append(self._current)
        elif tag.lower() == "input" and self._current is not None:
            name = values.get("name", "")
            if not name:
                return
            self._current.fields.append(
                FormField(
                    name=name,
                    value=values.get("value", ""),
                    kind=values.get("type", "text").lower(),
                )
            )
        elif tag.lower() == "textarea" and self._current is not None:
            name = values.get("name", "")
            if name:
                self._textarea = FormField(name=name, kind="textarea")
                self._current.fields.append(self._textarea)
        elif tag.lower() == "button" and self._current is not None:
            name = values.get("name", "")
            if name and values.get("type", "submit").lower() == "submit":
                self._current.fields.append(
                    FormField(name=name, value=values.get("value", ""), kind="submit")
                )

    def handle_data(self, data: str) -> None:
        if self._textarea is not None:
            self._textarea.value += data

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current = None
        elif tag.lower() == "textarea":
            self._textarea = None


def parse_forms(html: str) -> list[Form]:
    parser = FormParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.forms


def _pick_field(form: Form, kind: str, configured: str) -> str:
    if configured:
        return configured
    for item in form.fields:
        if item.kind == kind and item.name:
            return item.name
    if kind == "text":
        for item in form.fields:
            if item.kind in ("text", "email", "username") and item.name:
                return item.name
    return ""


@dataclass
class AuthResult:
    name: str
    ok: bool
    detail: str
    identity_kind: str
    cookies: tuple[str, ...] = ()
    checked_at: str = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "detail": self.detail,
            "identity_kind": self.identity_kind,
            "cookies": list(self.cookies),
            "checked_at": self.checked_at,
        }


class AuthenticationAgent:
    def __init__(self, config: Config, graph: Graph, audit: AuditLog):
        self.config = config
        self.graph = graph
        self.audit = audit

    async def authenticate(self, session: HttpSession, identity: IdentitySettings) -> AuthResult:
        if identity.headers:
            session.update_headers(identity.headers)
        if identity.kind == "bearer":
            session.set_header("Authorization", f"Bearer {identity.token}")
            result = await self._verify_header(session, identity, "bearer token set")
        elif identity.kind == "basic":
            token = base64.b64encode(f"{identity.username}:{identity.password}".encode()).decode(
                "ascii"
            )
            session.set_header("Authorization", f"Basic {token}")
            result = await self._verify_header(session, identity, "basic auth header set")
        elif identity.kind == "headers":
            result = await self._verify_header(session, identity, "custom headers set")
        elif identity.kind == "browser":
            result = await self._browser_login(session, identity)
        else:
            result = await self._form_login(session, identity)

        self.graph.upsert_node(
            "identity",
            identity.name,
            name=identity.name,
            kind=identity.kind,
            authenticated=result.ok,
            detail=result.detail,
            cookies=list(result.cookies),
        )
        self.audit.decision(
            "auth",
            "login",
            result.detail,
            identity=identity.name,
            ok=result.ok,
            cookies=list(result.cookies),
        )
        return result

    async def _verify_header(
        self, session: HttpSession, identity: IdentitySettings, detail: str
    ) -> AuthResult:
        if not identity.login_url:
            return AuthResult(identity.name, True, detail, identity.kind)
        try:
            response = await session.request("GET", identity.login_url, follow=True)
        except Exception as exc:
            return AuthResult(
                identity.name, False, f"{detail}; verification failed: {exc}", identity.kind
            )
        ok = response.status < 400
        reason = detail + (f"; verification returned {response.status}" if not ok else "")
        return AuthResult(
            identity.name,
            ok,
            reason,
            identity.kind,
            tuple(session.cookie_names()),
        )

    async def _form_login(self, session: HttpSession, identity: IdentitySettings) -> AuthResult:
        try:
            page = await session.request("GET", identity.login_url, follow=True)
        except Exception as exc:
            return AuthResult(identity.name, False, f"login page failed: {exc}", identity.kind)
        if page.status >= 400:
            return AuthResult(
                identity.name,
                False,
                f"login page returned {page.status}",
                identity.kind,
            )
        forms = parse_forms(page.text)
        form = next((item for item in forms if item.has_password()), None)
        if form is None:
            if identity.kind == "form":
                return AuthResult(
                    identity.name,
                    False,
                    'no password form found; use kind="browser" for JavaScript logins',
                    identity.kind,
                )
            return AuthResult(identity.name, False, "no password form found", identity.kind)

        username_field = _pick_field(form, "text", identity.username_field)
        password_field = _pick_field(form, "password", identity.password_field)
        if not username_field or not password_field:
            return AuthResult(
                identity.name,
                False,
                "could not identify username/password inputs",
                identity.kind,
            )

        data = form.named()
        data[username_field] = identity.username
        data[password_field] = identity.password
        data.update(identity.extra_fields)
        for item in form.fields:
            if item.kind == "submit" and item.name and item.name not in data:
                data[item.name] = item.value
                break

        action = urljoin(page.url, form.action) if form.action else page.url
        method = form.method.upper()
        if method == "POST" and not self.config.run.allow_post:
            return AuthResult(
                identity.name,
                False,
                "login form uses POST but run.allow_post is false",
                identity.kind,
            )
        headers = {"Referer": page.url}
        try:
            if method == "GET":
                response = await session.request(
                    "GET", action, params=data, follow=True, headers=headers
                )
            else:
                response = await session.request(
                    "POST", action, data=data, follow=True, headers=headers
                )
        except Exception as exc:
            return AuthResult(identity.name, False, f"login submit failed: {exc}", identity.kind)

        cookies = tuple(session.cookie_names())
        if identity.success_marker:
            ok = identity.success_marker in response.text
        else:
            no_form = not any(item.has_password() for item in parse_forms(response.text))
            ok = response.status < 400 and no_form and bool(cookies)
        detail = f"signed in as {identity.name}" if ok else "login did not reach a signed-in page"
        if not ok:
            detail += f" (status {response.status}, cookies: {', '.join(cookies) or 'none'})"
        return AuthResult(identity.name, ok, detail, identity.kind, cookies)

    async def _browser_login(self, session: HttpSession, identity: IdentitySettings) -> AuthResult:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return AuthResult(
                identity.name,
                False,
                "playwright is not installed (pip install 'redthread[browser]')",
                identity.kind,
            )
        html = ""
        try:
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()
                await page.goto(identity.login_url, wait_until="domcontentloaded", timeout=30000)
                username_selector = (
                    f'input[name="{identity.username_field}"]'
                    if identity.username_field
                    else 'input[type="text"], input[type="email"], input[name*="user" i]'
                )
                password_selector = (
                    f'input[name="{identity.password_field}"]'
                    if identity.password_field
                    else 'input[type="password"]'
                )
                await page.fill(username_selector, identity.username)
                await page.fill(password_selector, identity.password)
                for name, value in identity.extra_fields.items():
                    try:
                        await page.fill(f'input[name="{name}"]', value)
                    except Exception:
                        continue
                try:
                    await page.click('button[type="submit"], input[type="submit"]')
                except Exception:
                    await page.press(password_selector, "Enter")
                try:
                    await page.wait_for_load_state("networkidle", timeout=10000)
                except Exception:
                    pass
                html = await page.content()
                for cookie in await context.cookies():
                    session.set_cookie(
                        cookie["name"],
                        cookie["value"],
                        domain=cookie.get("domain", ""),
                        path=cookie.get("path", "/"),
                    )
                await browser.close()
        except Exception as exc:
            return AuthResult(identity.name, False, f"browser login failed: {exc}", identity.kind)

        if identity.success_marker:
            ok = identity.success_marker in html
        else:
            ok = not any(item.has_password() for item in parse_forms(html))
        return AuthResult(
            identity.name,
            ok,
            "browser sign-in completed" if ok else "browser sign-in did not leave the login page",
            identity.kind,
            tuple(session.cookie_names()),
        )
