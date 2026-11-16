from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from redthread.config import Config
from redthread.cvss import cvss_score, severity_for_score
from redthread.errors import RequestFailed
from redthread.graph import Graph
from redthread.http import HttpSession
from redthread.models import Endpoint, Finding, Severity, Status
from redthread.scope import Scope

if TYPE_CHECKING:
    from redthread.audit import AuditLog


@dataclass
class ValidationResult:
    ok: bool
    confidence: float = 0.0
    evidence: dict[str, Any] = field(default_factory=dict)
    note: str = ""


@dataclass
class CheckContext:
    config: Config
    graph: Graph
    scope: Scope
    sessions: dict[str, HttpSession]
    anonymous: HttpSession
    audit: AuditLog

    def session(self, identity: str | None = None) -> HttpSession:
        if identity and identity in self.sessions:
            return self.sessions[identity]
        return self.anonymous

    @property
    def identities(self) -> list[str]:
        return sorted(self.sessions)

    def finding(
        self,
        check: Check,
        endpoint: Endpoint,
        *,
        title: str | None = None,
        severity: Severity | None = None,
        parameter: str | None = None,
        evidence: dict[str, Any] | None = None,
        description: str | None = None,
        remediation: str | None = None,
        cvss_vector: str | None = None,
        confidence: float = 0.5,
        identity: str | None = None,
        variant: str = "",
    ) -> Finding:
        vector = cvss_vector if cvss_vector is not None else check.cvss
        score = cvss_score(vector)
        chosen = severity or (severity_for_score(score) if score else check.severity)
        return Finding(
            check_id=check.id,
            title=title or check.title,
            severity=chosen,
            method=endpoint.method,
            endpoint=endpoint.url,
            parameter=parameter,
            description=description if description is not None else check.description,
            remediation=remediation if remediation is not None else check.remediation,
            evidence=evidence or {},
            confidence=confidence,
            status=Status.CANDIDATE,
            discovered_by=f"{check.id}:{identity or 'anonymous'}",
            variant=variant,
            cvss_vector=vector,
            cvss_score=score,
        )


class Check:
    id: ClassVar[str] = ""
    title: ClassVar[str] = ""
    severity: ClassVar[Severity] = Severity.MEDIUM
    description: ClassVar[str] = ""
    remediation: ClassVar[str] = ""
    cvss: ClassVar[str] = ""
    safe_replay: ClassVar[bool] = True

    def action_key(self, endpoint: Endpoint, identity: str | None = None) -> str:
        return f"{self.id}|{endpoint.method}|{endpoint.url}|{identity or 'anonymous'}"

    def applies(self, endpoint: Endpoint) -> bool:
        return endpoint.method.upper() in ("GET", "HEAD", "OPTIONS")

    def enabled(self, config: Config, identities: list[str]) -> bool:
        return True

    async def run(
        self, ctx: CheckContext, endpoint: Endpoint, identity: str | None = None
    ) -> list[Finding]:
        raise NotImplementedError

    async def verify(self, ctx: CheckContext, finding: Finding) -> ValidationResult:
        raise NotImplementedError


def params_for(endpoint: Endpoint) -> dict[str, str]:
    params = dict(endpoint.params)
    parts = urlsplit(endpoint.url)
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        params.setdefault(key, value)
    return params


def replace_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    found = False
    updated = []
    for key, current in pairs:
        if key == name:
            updated.append((key, value))
            found = True
        else:
            updated.append((key, current))
    if not found:
        updated.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(updated), parts.fragment))


def clipped(text: str, limit: int = 700) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"... [{len(text) - limit} chars omitted]"


def body_similarity(left: str, right: str) -> float:
    if left == right:
        return 1.0
    if not left or not right:
        return 0.0
    return difflib.SequenceMatcher(None, left, right, autojunk=False).ratio()


def json_shape(value: Any) -> str:
    if isinstance(value, dict):
        return "{" + ",".join(sorted(str(key) for key in value)) + "}"
    if isinstance(value, list):
        return "[" + (json_shape(value[0]) if value else "") + "]"
    return type(value).__name__


def is_success(status: int) -> bool:
    return 200 <= status < 300


def is_object_id(value: str) -> bool:
    if re.fullmatch(r"\d{1,12}", value):
        return True
    return bool(
        re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
            r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
            value,
        )
    )


def object_id_from_endpoint(endpoint: Endpoint) -> tuple[str, str] | None:
    parts = urlsplit(endpoint.url)
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in (
            "id",
            "user_id",
            "account_id",
            "order_id",
            "object_id",
            "item",
        ) and is_object_id(value):
            return key, value
    for segment in parts.path.strip("/").split("/"):
        if is_object_id(segment):
            return "path", segment
    return None


def redact_cookie_header(value: str) -> str:
    name, separator, rest = value.partition("=")
    if not separator:
        return "REDACTED"
    attributes = []
    for part in rest.split(";"):
        attr = part.strip()
        lower = attr.lower()
        if lower.startswith(("path=", "domain=", "expires=", "max-age=", "samesite=")):
            attributes.append(attr)
        elif lower == "secure":
            attributes.append("Secure")
        elif lower == "httponly":
            attributes.append("HttpOnly")
    return f"{name}=REDACTED" + ("; " + "; ".join(attributes) if attributes else "")


async def safe_request(
    session: HttpSession,
    method: str,
    url: str,
    **kwargs: Any,
) -> Any:
    try:
        return await session.request(method, url, **kwargs)
    except RequestFailed:
        return None
