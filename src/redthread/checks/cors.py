from __future__ import annotations

from redthread.checks.base import Check, CheckContext, ValidationResult
from redthread.models import Endpoint, Finding, Severity

_PROBE_ORIGIN = "https://redthread.invalid"


class CorsCheck(Check):
    id = "cors"
    title = "Permissive cross-origin access"
    severity = Severity.MEDIUM
    description = (
        "The endpoint reflects an arbitrary Origin and allows credentials. A page "
        "on any site can therefore read authenticated responses from this endpoint."
    )
    remediation = (
        "Allow only trusted origins from an explicit allowlist. Never combine a "
        "reflected or wildcard Access-Control-Allow-Origin with credentials."
    )
    cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N"

    def applies(self, endpoint: Endpoint) -> bool:
        if endpoint.method.upper() != "GET":
            return False
        path = endpoint.path.lower()
        return (
            "api" in endpoint.tags
            or "graphql" in endpoint.tags
            or "/api/" in path
            or path.endswith("/graphql")
        )

    async def run(
        self, ctx: CheckContext, endpoint: Endpoint, identity: str | None = None
    ) -> list[Finding]:
        session = ctx.session(identity)
        response = await session.request(
            "GET",
            endpoint.url,
            headers={"Origin": _PROBE_ORIGIN, "Accept": "application/json"},
        )
        allow_origin = response.header("access-control-allow-origin")
        allow_credentials = response.header("access-control-allow-credentials").lower()
        if allow_origin == _PROBE_ORIGIN and allow_credentials == "true":
            evidence = {
                "request_origin": _PROBE_ORIGIN,
                "access-control-allow-origin": allow_origin,
                "access-control-allow-credentials": allow_credentials,
                "status": response.status,
                "body_excerpt": response.snippet(240),
            }
            return [
                ctx.finding(
                    self,
                    endpoint,
                    evidence=evidence,
                    confidence=0.9,
                    identity=identity,
                )
            ]
        return []

    async def verify(self, ctx: CheckContext, finding: Finding) -> ValidationResult:
        identity = finding.discovered_by.rsplit(":", 1)[-1]
        identity = None if identity == "anonymous" else identity
        response = await ctx.session(identity).request(
            "GET",
            finding.endpoint,
            headers={"Origin": _PROBE_ORIGIN, "Accept": "application/json"},
        )
        ok = (
            response.header("access-control-allow-origin") == _PROBE_ORIGIN
            and response.header("access-control-allow-credentials").lower() == "true"
        )
        evidence = {
            "recheck_status": response.status,
            "access-control-allow-origin": response.header("access-control-allow-origin"),
            "access-control-allow-credentials": response.header("access-control-allow-credentials"),
        }
        return ValidationResult(
            ok,
            0.9 if ok else 0.2,
            evidence,
            "the Origin reflection was repeated with the same probe origin",
        )
