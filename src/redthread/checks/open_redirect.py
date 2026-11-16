from __future__ import annotations

import secrets
from urllib.parse import urlsplit

from redthread.checks.base import (
    Check,
    CheckContext,
    ValidationResult,
    params_for,
    replace_param,
)
from redthread.models import Endpoint, Finding, Severity

_REDIRECT_PARAMS = {
    "next",
    "url",
    "redirect",
    "redirect_uri",
    "return",
    "return_to",
    "continue",
    "target",
    "dest",
    "destination",
    "callback",
}


class OpenRedirectCheck(Check):
    id = "open-redirect"
    title = "Open redirect"
    severity = Severity.MEDIUM
    description = (
        "A redirect parameter accepts an absolute external URL and sends the "
        "browser there. This is used for phishing and for bypassing allowlists "
        "in OAuth or SSO flows."
    )
    remediation = (
        "Resolve redirect targets against an allowlist of paths or hosts. Reject "
        "absolute and scheme-relative URLs unless the exact destination is approved."
    )
    cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"

    def applies(self, endpoint: Endpoint) -> bool:
        return endpoint.method.upper() == "GET" and bool(
            set(params_for(endpoint)) & _REDIRECT_PARAMS
        )

    async def run(
        self, ctx: CheckContext, endpoint: Endpoint, identity: str | None = None
    ) -> list[Finding]:
        params = [name for name in params_for(endpoint) if name.lower() in _REDIRECT_PARAMS]
        session = ctx.session(identity)
        for name in params[:3]:
            marker = f"rt-{secrets.token_hex(4)}"
            payload = f"https://redthread.invalid/{marker}"
            url = replace_param(endpoint.url, name, payload)
            response = await session.request("GET", url, follow=False)
            location = response.header("location")
            if not location or not (300 <= response.status < 400):
                continue
            target = urlsplit(location)
            if target.hostname == "redthread.invalid" or marker in location:
                evidence = {
                    "parameter": name,
                    "payload": payload,
                    "status": response.status,
                    "location": location,
                    "request_url": url,
                }
                return [
                    ctx.finding(
                        self,
                        endpoint,
                        parameter=name,
                        evidence=evidence,
                        confidence=0.95,
                        identity=identity,
                    )
                ]
        return []

    async def verify(self, ctx: CheckContext, finding: Finding) -> ValidationResult:
        parameter = finding.parameter or ""
        payload = finding.evidence.get("payload", "")
        if not parameter or not payload:
            return ValidationResult(False, 0.0, note="probe details were incomplete")
        identity = finding.discovered_by.rsplit(":", 1)[-1]
        identity = None if identity == "anonymous" else identity
        url = replace_param(finding.endpoint, parameter, payload)
        response = await ctx.session(identity).request("GET", url, follow=False)
        location = response.header("location")
        ok = 300 <= response.status < 400 and "redthread.invalid" in location.lower()
        evidence = {
            "recheck_status": response.status,
            "location": location,
            "payload": payload,
        }
        return ValidationResult(
            ok,
            0.95 if ok else 0.1,
            evidence,
            "the same redirect payload was replayed without following redirects",
        )
