from __future__ import annotations

from typing import Any

from redthread.checks.base import (
    Check,
    CheckContext,
    ValidationResult,
    body_similarity,
    clipped,
    is_success,
    object_id_from_endpoint,
)
from redthread.models import Endpoint, Finding, Severity


class ObjectAuthzCheck(Check):
    id = "authz-object"
    title = "Object-level authorization bypass"
    severity = Severity.HIGH
    description = (
        "Two authenticated identities receive the same object from an endpoint that "
        "contains an object identifier. The anonymous request is checked as well, so "
        "a genuinely public resource is not reported."
    )
    remediation = (
        "Authorise every object access against the current subject on the server. "
        "Do not rely on unguessable identifiers or on hiding links in the UI."
    )
    cvss = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N"

    def applies(self, endpoint: Endpoint) -> bool:
        return endpoint.method.upper() == "GET" and object_id_from_endpoint(endpoint) is not None

    def enabled(self, config, identities: list[str]) -> bool:
        return len(identities) >= 2

    async def run(
        self, ctx: CheckContext, endpoint: Endpoint, identity: str | None = None
    ) -> list[Finding]:
        if len(ctx.identities) < 2:
            return []
        object_ref = object_id_from_endpoint(endpoint)
        if not object_ref:
            return []
        param, value = object_ref
        victims = [name for name in endpoint.identities if name in ctx.sessions]
        if not victims:
            return []

        findings: list[Finding] = []
        for victim in victims:
            victim_response = await ctx.session(victim).request("GET", endpoint.url)
            if not is_success(victim_response.status):
                continue
            for attacker in ctx.identities:
                if attacker == victim:
                    continue
                attacker_response = await ctx.session(attacker).request("GET", endpoint.url)
                if not is_success(attacker_response.status):
                    continue
                anonymous = await ctx.anonymous.request("GET", endpoint.url)
                if is_success(anonymous.status):
                    public_similarity = body_similarity(victim_response.text, anonymous.text)
                    if public_similarity >= 0.92:
                        continue
                similarity = body_similarity(victim_response.text, attacker_response.text)
                if similarity < 0.9 or len(victim_response.text) < 40:
                    continue
                evidence: dict[str, Any] = {
                    "object_reference": {"location": param, "value": value},
                    "victim": victim,
                    "attacker": attacker,
                    "victim_status": victim_response.status,
                    "attacker_status": attacker_response.status,
                    "anonymous_status": anonymous.status,
                    "body_similarity": round(similarity, 3),
                    "body_excerpt": clipped(attacker_response.text, 500),
                }
                findings.append(
                    ctx.finding(
                        self,
                        endpoint,
                        parameter=param if param != "path" else value,
                        evidence=evidence,
                        confidence=0.82,
                        identity=attacker,
                        variant=f"{attacker}->{victim}",
                    )
                )
                break
        return findings

    async def verify(self, ctx: CheckContext, finding: Finding) -> ValidationResult:
        victim = finding.evidence.get("victim", "")
        attacker = finding.evidence.get("attacker", "")
        if victim not in ctx.sessions or attacker not in ctx.sessions:
            return ValidationResult(False, 0.0, note="identity session is no longer available")
        victim_response = await ctx.session(victim).request("GET", finding.endpoint)
        attacker_response = await ctx.session(attacker).request("GET", finding.endpoint)
        anonymous = await ctx.anonymous.request("GET", finding.endpoint)
        if not is_success(victim_response.status) or not is_success(attacker_response.status):
            return ValidationResult(
                False,
                0.1,
                {
                    "victim_status": victim_response.status,
                    "attacker_status": attacker_response.status,
                },
                "one of the identities no longer receives a successful response",
            )
        similarity = body_similarity(victim_response.text, attacker_response.text)
        public = (
            is_success(anonymous.status)
            and body_similarity(victim_response.text, anonymous.text) >= 0.92
        )
        ok = similarity >= 0.88 and not public
        evidence = {
            "victim_status": victim_response.status,
            "attacker_status": attacker_response.status,
            "anonymous_status": anonymous.status,
            "body_similarity": round(similarity, 3),
        }
        return ValidationResult(
            ok,
            0.82 if ok else 0.1,
            evidence,
            "both identities and an anonymous client were replayed against the object",
        )
