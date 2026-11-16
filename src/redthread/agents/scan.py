from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit

from redthread.agents.auth import Form, parse_forms
from redthread.audit import AuditLog
from redthread.config import Config
from redthread.discovery import is_dangerous, links_from_html, normalise_url
from redthread.errors import RequestFailed, ScopeError
from redthread.graph import Graph
from redthread.http import HttpSession
from redthread.integrations.graphql import INTROSPECTION_QUERY, schema_fields
from redthread.integrations.nmap import NmapRunner
from redthread.integrations.openapi import parse_openapi
from redthread.models import Endpoint
from redthread.scope import Scope

_SPEC_PATHS = (
    "openapi.json",
    "swagger.json",
    "v3/api-docs",
    "api/openapi.json",
    "swagger/v1/swagger.json",
)
_GRAPHQL_PATHS = ("graphql", "api/graphql")


@dataclass
class ScanReport:
    pages: int = 0
    endpoints: int = 0
    identities: int = 0
    specs: list[str] = field(default_factory=list)
    graphql: list[str] = field(default_factory=list)
    services: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pages": self.pages,
            "endpoints": self.endpoints,
            "identities": self.identities,
            "specs": list(self.specs),
            "graphql": list(self.graphql),
            "services": self.services,
            "errors": list(self.errors),
        }


class ScanAgent:
    def __init__(
        self,
        config: Config,
        scope: Scope,
        graph: Graph,
        audit: AuditLog,
    ):
        self.config = config
        self.scope = scope
        self.graph = graph
        self.audit = audit
        self.report = ScanReport()
        self._visited: set[tuple[str, str]] = set()
        self._hosts: set[str] = set()
        self._specs_seen: set[str] = set()
        self._graphql_seen: set[str] = set()

    async def run(
        self,
        anonymous: HttpSession,
        sessions: dict[str, HttpSession],
    ) -> ScanReport:
        allowed = {**sessions}
        seed_session = next(iter(allowed.values()), anonymous)
        seed_identity = next(iter(allowed), "anonymous")
        await self._discover_specs(seed_session, seed_identity)

        if self.config.scope.crawl_identities:
            await self._crawl(anonymous, "anonymous")
            for name, session in allowed.items():
                if self.report.pages >= self.config.scope.max_pages:
                    break
                await self._crawl(session, name)
        else:
            await self._crawl(anonymous, "anonymous")

        if self.config.integrations.nmap_enabled:
            await self._nmap()

        self.report.endpoints = self.graph.count_nodes("endpoint")
        self.report.identities = len(sessions)
        self.audit.record("scan_complete", **self.report.to_dict())
        return self.report

    async def _crawl(self, session: HttpSession, identity: str) -> None:
        queue: list[tuple[str, int]] = [(seed, 0) for seed in self.scope.seeds]
        while queue and self.report.pages < self.config.scope.max_pages:
            raw_url, depth = queue.pop(0)
            url = normalise_url(raw_url, raw_url)
            if not url:
                continue
            key = (identity, url)
            if key in self._visited:
                continue
            self._visited.add(key)
            if self._is_dangerous(url):
                self.audit.decision("scan", "skip", "destructive-looking path", url=url)
                continue
            try:
                self.scope.check(url, "GET")
            except ScopeError as exc:
                self.audit.decision("scan", "skip", str(exc), url=url)
                continue
            try:
                response = await session.request("GET", url, follow=True)
            except RequestFailed as exc:
                self.report.errors.append(str(exc))
                continue
            self.report.pages += 1

            final_url = normalise_url(response.url, response.url) or response.url
            self._record_host(final_url)
            tags = self._tags_for(url, response.content_type)
            tags.update(self._tags_for(final_url, response.content_type))
            if response.history:
                tags.add("redirect")
            identities = (identity,) if identity != "anonymous" else ()
            self.graph.upsert_endpoint(
                Endpoint(
                    method="GET",
                    url=url,
                    params=dict(parse_qsl(urlsplit(url).query, keep_blank_values=True)),
                    source="crawl",
                    identities=identities,
                    tags=tuple(tags),
                )
            )
            if final_url != url:
                self.graph.upsert_endpoint(
                    Endpoint(
                        method="GET",
                        url=final_url,
                        params=dict(parse_qsl(urlsplit(final_url).query, keep_blank_values=True)),
                        source="crawl",
                        identities=identities,
                        tags=tuple(self._tags_for(final_url, response.content_type)),
                    )
                )

            if response.is_html:
                for form in parse_forms(response.text):
                    self._record_form(form, response.url, identity)
                if depth < self.config.scope.max_depth:
                    links = links_from_html(response.text)
                    for link in list(links)[:250]:
                        candidate = normalise_url(response.url, link)
                        if not candidate:
                            continue
                        if self.config.scope.same_origin and not self.scope.is_same_origin(
                            candidate
                        ):
                            continue
                        try:
                            self.scope.check(candidate, "GET")
                        except ScopeError:
                            continue
                        if (identity, candidate) not in self._visited:
                            queue.append((candidate, depth + 1))

    def _record_form(self, form: Form, page_url: str, identity: str) -> None:
        action = urljoin(page_url, form.action) if form.action else page_url
        normal = normalise_url(page_url, action)
        if not normal or self._is_dangerous(normal):
            return
        try:
            self.scope.check(normal, form.method.upper())
        except ScopeError:
            return
        params = {
            field.name: field.value
            for field in form.fields
            if field.name and field.kind not in ("submit", "button", "file")
        }
        endpoint = Endpoint(
            method=form.method.upper(),
            url=normal,
            params=params,
            source="form",
            identities=(identity,) if identity != "anonymous" else (),
            tags=("form",),
            note="discovered from an HTML form",
        )
        self.graph.upsert_endpoint(endpoint)

    def _tags_for(self, url: str, content_type: str) -> set[str]:
        tags: set[str] = set()
        path = urlsplit(url).path.lower()
        if "html" in content_type:
            tags.add("html")
        if "json" in content_type:
            tags.add("json")
        if "/api/" in path or path.endswith("/api") or "graphql" in path:
            tags.add("api")
        if path.endswith("/graphql"):
            tags.add("graphql")
        return tags

    def _record_host(self, url: str) -> None:
        parts = urlsplit(url)
        host = parts.netloc.lower()
        if not host:
            return
        self.graph.upsert_node("host", host, scheme=parts.scheme, hostname=parts.hostname)
        self._hosts.add(host)

    def _is_dangerous(self, url: str) -> bool:
        return is_dangerous(url)

    async def _discover_specs(self, session: HttpSession, identity: str) -> None:
        bases: list[str] = []
        for seed in self.scope.seeds:
            bases.append(seed.rstrip("/"))
        for origin in self.scope.origins:
            if origin not in bases:
                bases.append(origin)
        for base in dict.fromkeys(bases):
            for suffix in _SPEC_PATHS:
                candidate = f"{base}/{suffix}"
                if candidate in self._specs_seen:
                    continue
                self._specs_seen.add(candidate)
                try:
                    self.scope.check(candidate, "GET")
                except ScopeError:
                    continue
                try:
                    response = await session.request("GET", candidate, follow=True)
                except RequestFailed:
                    continue
                if response.status >= 400 or not response.text.strip():
                    continue
                spec = self._parse_spec(response.text)
                if spec is None:
                    continue
                try:
                    endpoints = parse_openapi(spec, base)
                except Exception as exc:
                    self.report.errors.append(f"could not parse {candidate}: {exc}")
                    continue
                if not endpoints:
                    continue
                self.report.specs.append(candidate)
                self.graph.upsert_node(
                    "document",
                    candidate,
                    kind="openapi",
                    title=str(spec.get("info", {}).get("title", "")),
                    source="scan",
                )
                for endpoint in endpoints:
                    if identity != "anonymous":
                        endpoint = endpoint.with_identity(identity)
                    try:
                        self.scope.check(endpoint.url, endpoint.method)
                    except ScopeError:
                        continue
                    self.graph.upsert_endpoint(endpoint)
                self.audit.record("spec_import", url=candidate, endpoints=len(endpoints))

            for suffix in _GRAPHQL_PATHS:
                candidate = f"{base}/{suffix}"
                if candidate in self._graphql_seen:
                    continue
                self._graphql_seen.add(candidate)
                try:
                    self.scope.check(candidate, "POST" if self.config.run.allow_post else "GET")
                except ScopeError:
                    continue
                payload: dict[str, Any]
                try:
                    if self.config.run.allow_post:
                        response = await session.request(
                            "POST",
                            candidate,
                            json={"query": INTROSPECTION_QUERY},
                            headers={"Content-Type": "application/json"},
                        )
                    else:
                        response = await session.request(
                            "GET", candidate, params={"query": INTROSPECTION_QUERY}
                        )
                except RequestFailed:
                    continue
                if response.status >= 400:
                    continue
                try:
                    payload = response.json()
                except ValueError:
                    continue
                fields = schema_fields(payload)
                if not fields:
                    continue
                self.report.graphql.append(candidate)
                endpoint = Endpoint(
                    method="GET",
                    url=candidate,
                    params={},
                    source="graphql",
                    identities=(identity,) if identity != "anonymous" else (),
                    tags=("api", "graphql"),
                    note="discovered through introspection",
                )
                node = self.graph.upsert_endpoint(endpoint)
                self.graph.upsert_node("endpoint", endpoint.key, graphql_fields=fields)
                self.graph.link(
                    ("endpoint", endpoint.key),
                    ("document", candidate),
                    "DESCRIBED_BY",
                )
                self.graph.upsert_node("document", candidate, kind="graphql", source="scan")
                self.audit.record(
                    "graphql_import",
                    url=candidate,
                    query_fields=len(fields.get("query", [])),
                    mutation_fields=len(fields.get("mutation", [])),
                    node=node,
                )

    @staticmethod
    def _parse_spec(text: str) -> dict[str, Any] | None:
        text = text.lstrip("\ufeff").strip()
        if text.startswith("{"):
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                return None
            return data if isinstance(data, dict) else None
        if text.startswith(("openapi:", "swagger:")):
            try:
                import yaml
            except ImportError:
                return None
            try:
                data = yaml.safe_load(text)
            except Exception:
                return None
            return data if isinstance(data, dict) else None
        return None

    async def _nmap(self) -> None:
        runner = NmapRunner(
            self.config.integrations.nmap_binary, self.config.integrations.nmap_args
        )
        result = await runner.scan(self.scope.seeds)
        if result.error:
            self.report.errors.append(f"nmap: {result.error}")
            return
        for host in result.hosts:
            self.graph.upsert_node("host", host, source="nmap")
        for service in result.services:
            if service.state != "open":
                continue
            key = f"{service.host}:{service.port}/{service.protocol}"
            service_node = self.graph.upsert_node(
                "service",
                key,
                host=service.host,
                port=service.port,
                protocol=service.protocol,
                name=service.name,
                product=service.product,
                version=service.version,
            )
            host_id = self.graph.upsert_node("host", service.host)
            self.graph.add_edge(host_id, service_node, "RUNS")
            self.report.services += 1
