from __future__ import annotations

from urllib.parse import urlsplit

from redthread.checks.base import Check, CheckContext, ValidationResult
from redthread.models import Endpoint, Finding, Severity
from redthread.scope import Scope

_HEADERS = (
    ("content-security-policy", "Content-Security-Policy"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("x-frame-options", "X-Frame-Options"),
    ("referrer-policy", "Referrer-Policy"),
)


class HeaderCheck(Check):
    id = "headers"
    title = "Missing baseline security headers"
    severity = Severity.LOW
    description = (
        "The response omits one or more headers that reduce the impact of "
        "content sniffing, framing and script injection. Missing headers are "
        "not a vulnerability on their own; they are reported as hardening gaps."
    )
    remediation = (
        "Send a restrictive Content-Security-Policy, X-Content-Type-Options: nosniff, "
        "an anti-framing policy, and a Referrer-Policy. Add HSTS on HTTPS sites."
    )

    def action_key(self, endpoint: Endpoint, identity: str | None = None) -> str:
        return f"{self.id}|{Scope.origin(endpoint.url)}"

    async def run(
        self, ctx: CheckContext, endpoint: Endpoint, identity: str | None = None
    ) -> list[Finding]:
        response = await ctx.session(identity).request("GET", endpoint.url)
        if response.status >= 500:
            return []

        missing: list[str] = []
        for header, label in _HEADERS:
            if header == "x-frame-options":
                csp = response.header("content-security-policy").lower()
                if "frame-ancestors" in csp:
                    continue
            if not response.header(header):
                missing.append(label)
        if urlsplit(endpoint.url).scheme == "https" and not response.header(
            "strict-transport-security"
        ):
            missing.append("Strict-Transport-Security")

        banners = {
            name: response.header(name)
            for name in ("server", "x-powered-by")
            if response.header(name)
        }
        weak_cors = (
            response.header("access-control-allow-origin") == "*"
            and response.header("access-control-allow-credentials").lower() == "true"
        )
        if weak_cors:
            missing.append("CORS wildcard with credentials")

        if not missing and not banners:
            return []

        evidence = {
            "url": endpoint.url,
            "status": response.status,
            "missing": missing,
            "banners": banners,
            "response_headers": response.to_evidence()["headers"],
        }
        title = f"Missing security headers on {endpoint.host}"
        return [
            ctx.finding(
                self,
                endpoint,
                title=title,
                evidence=evidence,
                confidence=0.95,
                identity=identity,
            )
        ]

    async def verify(self, ctx: CheckContext, finding: Finding) -> ValidationResult:
        identity = finding.discovered_by.rsplit(":", 1)[-1]
        identity = None if identity == "anonymous" else identity
        response = await ctx.session(identity).request("GET", finding.endpoint)
        missing = [
            label
            for header, label in _HEADERS
            if not response.header(header)
            and not (
                header == "x-frame-options"
                and "frame-ancestors" in response.header("content-security-policy").lower()
            )
        ]
        if response.status >= 500:
            return ValidationResult(False, 0.3, note=f"target returned {response.status}")
        return ValidationResult(
            bool(missing),
            0.95 if missing else 0.2,
            {"recheck_status": response.status, "still_missing": missing},
            "headers were re-read on a second request",
        )
