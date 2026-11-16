from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

from redthread.agents.auth import parse_forms
from redthread.checks import Check, CheckContext
from redthread.discovery import is_dangerous, links_from_html, normalise_url
from redthread.errors import BudgetExceeded, RequestFailed, RunStopped, ScopeError
from redthread.graph import Graph
from redthread.models import Endpoint, Finding, Status, utcnow
from redthread.planner import ActionCandidate

log = logging.getLogger(__name__)


@dataclass
class ActionResult:
    action: ActionCandidate
    status: str = "no-result"
    reward: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    candidates: int = 0
    rejected_count: int = 0
    new_endpoints: int = 0
    error: str = ""

    @property
    def validated(self) -> int:
        return len(self.findings)


class ActionRunner:
    def __init__(
        self,
        graph: Graph,
        checks: dict[str, Check],
        ctx: CheckContext,
        audit: Any,
    ):
        self.graph = graph
        self.checks = checks
        self.ctx = ctx
        self.audit = audit

    async def run(self, action: ActionCandidate, phase: str) -> ActionResult:
        if action.kind == "request":
            return await self._run_request(action, phase)
        return await self._run_check(action, phase)

    async def _run_check(self, action: ActionCandidate, phase: str) -> ActionResult:
        check = self.checks.get(action.check_id)
        result = ActionResult(action=action)
        if check is None or action.endpoint is None:
            result.error = "check is no longer registered"
            return result
        try:
            candidates = await check.run(self.ctx, action.endpoint, action.identity)
        except (BudgetExceeded, RunStopped):
            raise
        except Exception as exc:  # a broken check should not end the run
            result.status = "error"
            result.error = f"{type(exc).__name__}: {exc}"
            log.warning("check %s failed on %s: %s", check.id, action.endpoint.url, exc)
            self.graph.record_action(action.key, phase, "error", 0.0, {"error": result.error})
            return result

        result.candidates = len(candidates)
        for finding in candidates:
            validated = await self.verify_finding(check, finding)
            if validated.status == Status.VALIDATED:
                result.findings.append(validated)
            else:
                result.rejected_count += 1

        if result.findings:
            result.status = "validated"
            result.reward = max(item.severity.weight for item in result.findings)
        elif candidates:
            result.status = "rejected"
            result.reward = 0.05
        else:
            result.status = "no-result"
            result.reward = 0.0

        self.graph.record_action(
            action.key,
            phase,
            result.status,
            result.reward,
            {
                "check": check.id,
                "endpoint": action.endpoint.url,
                "identity": action.identity,
                "candidates": result.candidates,
                "validated": [item.id for item in result.findings],
            },
        )
        return result

    async def verify_finding(self, check: Check, finding: Finding) -> Finding:
        try:
            verdict = await check.verify(self.ctx, finding)
        except (BudgetExceeded, RunStopped):
            raise
        except Exception as exc:
            verdict_note = f"validator raised {type(exc).__name__}: {exc}"
            finding.status = Status.REJECTED
            finding.verified_at = utcnow()
            finding.confidence = min(finding.confidence, 0.2)
            finding.evidence = {**finding.evidence, "validation_note": verdict_note}
            self.graph.save_finding(finding)
            self.audit.record(
                "finding",
                id=finding.id,
                check=check.id,
                status="rejected",
                endpoint=finding.endpoint,
                note=verdict_note,
            )
            return finding

        finding.verified_at = utcnow()
        finding.confidence = float(verdict.confidence)
        finding.evidence = {**finding.evidence, "validation": verdict.evidence}
        if verdict.note:
            finding.evidence["validation_note"] = verdict.note
        finding.status = Status.VALIDATED if verdict.ok else Status.REJECTED
        if not verdict.ok:
            finding.confidence = min(finding.confidence, 0.2)
        self.graph.save_finding(finding)
        self.audit.record(
            "finding",
            id=finding.id,
            check=check.id,
            status=finding.status.value,
            endpoint=finding.endpoint,
            parameter=finding.parameter,
            confidence=finding.confidence,
        )
        return finding

    async def _run_request(self, action: ActionCandidate, phase: str) -> ActionResult:
        result = ActionResult(action=action)
        payload = action.payload
        method = str(payload.get("method", "GET")).upper()
        url = str(payload.get("url", ""))
        if method not in ("GET", "HEAD", "OPTIONS"):
            result.error = f"request action used {method}"
            return result
        if not url or is_dangerous(url):
            result.error = "request action pointed at a destructive or empty URL"
            return result
        session = self.ctx.session(action.identity)
        before = self.graph.count_nodes("endpoint")
        try:
            response = await session.request(method, url, follow=True)
        except (BudgetExceeded, RunStopped):
            raise
        except (RequestFailed, ScopeError) as exc:
            result.status = "error"
            result.error = str(exc)
            self.graph.record_action(action.key, phase, "error", 0.0, {"error": str(exc)})
            return result

        new = 0
        if response.is_html:
            new += self._record_links(response.url, response.text, action.identity)
            new += self._record_forms(response.url, response.text, action.identity)
        result.new_endpoints = max(0, self.graph.count_nodes("endpoint") - before)
        result.status = "new-endpoint" if result.new_endpoints else "no-result"
        result.reward = 0.3 if result.new_endpoints else 0.0
        self.graph.record_action(
            action.key,
            phase,
            result.status,
            result.reward,
            {
                "url": url,
                "status": response.status,
                "new_endpoints": result.new_endpoints,
                "reason": payload.get("why", ""),
            },
        )
        return result

    def _record_links(self, base: str, html: str, identity: str) -> int:
        added = 0
        for link in list(links_from_html(html))[:80]:
            url = normalise_url(base, link)
            if not url or is_dangerous(url):
                continue
            try:
                if not self.ctx.scope.is_same_origin(url):
                    continue
                self.ctx.scope.check(url, "GET")
            except ScopeError:
                continue
            existed = self.graph.get_node("endpoint", f"GET {url}")
            self.graph.upsert_endpoint(
                Endpoint(
                    method="GET",
                    url=url,
                    source="llm",
                    identities=(identity,) if identity != "anonymous" else (),
                    tags=("discovered",),
                )
            )
            if not existed:
                added += 1
        return added

    def _record_forms(self, base: str, html: str, identity: str) -> int:
        added = 0
        for form in parse_forms(html):
            action = urljoin(base, form.action) if form.action else base
            normal = normalise_url(base, action)
            if not normal or is_dangerous(normal):
                continue
            try:
                self.ctx.scope.check(normal, form.method.upper())
            except ScopeError:
                continue
            existed = self.graph.get_node("endpoint", f"{form.method} {normal}")
            self.graph.upsert_endpoint(
                Endpoint(
                    method=form.method.upper(),
                    url=normal,
                    params={
                        field.name: field.value
                        for field in form.fields
                        if field.name and field.kind not in ("submit", "button", "file")
                    },
                    source="llm",
                    identities=(identity,) if identity != "anonymous" else (),
                    tags=("form", "discovered"),
                )
            )
            if not existed:
                added += 1
        return added
