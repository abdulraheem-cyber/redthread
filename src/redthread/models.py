from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


def utcnow() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }[self.value]

    @property
    def weight(self) -> float:
        return {
            "info": 0.1,
            "low": 0.3,
            "medium": 0.6,
            "high": 0.9,
            "critical": 1.0,
        }[self.value]

    @classmethod
    def from_rank(cls, rank: int) -> Severity:
        for item in cls:
            if item.rank == rank:
                return item
        raise ValueError(f"unknown severity rank {rank}")


class Status(StrEnum):
    CANDIDATE = "candidate"
    VALIDATED = "validated"
    REJECTED = "rejected"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class Endpoint:
    method: str
    url: str
    params: dict[str, str] = field(default_factory=dict)
    source: str = "crawl"
    identities: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    note: str = ""

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.url}"

    @property
    def path(self) -> str:
        from urllib.parse import urlsplit

        return urlsplit(self.url).path or "/"

    @property
    def host(self) -> str:
        from urllib.parse import urlsplit

        return urlsplit(self.url).netloc

    def with_identity(self, identity: str) -> Endpoint:
        if identity in self.identities:
            return self
        return Endpoint(
            method=self.method,
            url=self.url,
            params=self.params,
            source=self.source,
            identities=tuple(sorted((*self.identities, identity))),
            tags=self.tags,
            note=self.note,
        )

    def with_tags(self, *tags: str) -> Endpoint:
        merged = tuple(sorted(set(self.tags) | set(tags)))
        if merged == self.tags:
            return self
        return Endpoint(
            method=self.method,
            url=self.url,
            params=self.params,
            source=self.source,
            identities=self.identities,
            tags=merged,
            note=self.note,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "params": self.params,
            "source": self.source,
            "identities": list(self.identities),
            "tags": list(self.tags),
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Endpoint:
        return cls(
            method=data["method"],
            url=data["url"],
            params=dict(data.get("params") or {}),
            source=data.get("source", "crawl"),
            identities=tuple(data.get("identities") or ()),
            tags=tuple(data.get("tags") or ()),
            note=data.get("note", ""),
        )


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    elapsed_ms: float
    set_cookies: tuple[str, ...] = ()
    history: tuple[str, ...] = ()

    @property
    def text(self) -> str:
        content_type = self.headers.get("content-type", "")
        charset = "utf-8"
        for part in content_type.split(";"):
            part = part.strip()
            if part.lower().startswith("charset="):
                charset = part.split("=", 1)[1].strip().strip('"')
                break
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type

    @property
    def is_json(self) -> bool:
        return "json" in self.content_type or self.content_type.endswith("+json")

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def json(self) -> Any:
        return json.loads(self.text)

    def snippet(self, limit: int = 500) -> str:
        text = self.text
        if len(text) <= limit:
            return text
        return text[:limit] + f"... [{len(text) - limit} chars omitted]"

    def to_evidence(self, limit: int = 500) -> dict[str, Any]:
        keep = (
            "content-type",
            "content-length",
            "location",
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "server",
            "x-powered-by",
            "x-content-type-options",
            "content-security-policy",
            "x-frame-options",
            "strict-transport-security",
        )
        headers = {k: self.headers[k] for k in keep if k in self.headers}
        return {
            "url": self.url,
            "status": self.status,
            "headers": headers,
            "body": self.snippet(limit),
            "elapsed_ms": round(self.elapsed_ms, 1),
        }


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    method: str
    endpoint: str
    parameter: str | None = None
    description: str = ""
    remediation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    status: Status = Status.CANDIDATE
    discovered_by: str = ""
    variant: str = ""
    cvss_vector: str = ""
    cvss_score: float = 0.0
    created_at: str = field(default_factory=utcnow)
    verified_at: str | None = None
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            raw = "|".join(
                [
                    self.check_id,
                    self.method.upper(),
                    self.endpoint,
                    self.parameter or "",
                    self.variant,
                ]
            )
            self.id = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "method": self.method,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "confidence": round(float(self.confidence), 3),
            "status": self.status.value,
            "discovered_by": self.discovered_by,
            "variant": self.variant,
            "cvss_vector": self.cvss_vector,
            "cvss_score": round(float(self.cvss_score), 1),
            "created_at": self.created_at,
            "verified_at": self.verified_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            check_id=data["check_id"],
            title=data["title"],
            severity=Severity(data["severity"]),
            method=data.get("method", "GET"),
            endpoint=data["endpoint"],
            parameter=data.get("parameter"),
            description=data.get("description", ""),
            remediation=data.get("remediation", ""),
            evidence=data.get("evidence") or {},
            confidence=float(data.get("confidence", 0.0)),
            status=Status(data.get("status", "candidate")),
            discovered_by=data.get("discovered_by", ""),
            variant=data.get("variant", ""),
            cvss_vector=data.get("cvss_vector", ""),
            cvss_score=float(data.get("cvss_score", 0.0)),
            created_at=data.get("created_at", utcnow()),
            verified_at=data.get("verified_at"),
            id=data.get("id", ""),
        )


@dataclass
class RunStats:
    requests: int = 0
    pages: int = 0
    endpoints: int = 0
    actions: int = 0
    findings: int = 0
    validated: int = 0
    rejected: int = 0
    llm_calls: int = 0
    started_at: str = field(default_factory=utcnow)
    finished_at: str | None = None
    stopped_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "requests": self.requests,
            "pages": self.pages,
            "endpoints": self.endpoints,
            "actions": self.actions,
            "findings": self.findings,
            "validated": self.validated,
            "rejected": self.rejected,
            "llm_calls": self.llm_calls,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "stopped_reason": self.stopped_reason,
        }
