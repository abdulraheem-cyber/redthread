from __future__ import annotations

import secrets
from typing import Any

from redthread.checks.base import (
    Check,
    CheckContext,
    ValidationResult,
    clipped,
    params_for,
    replace_param,
)
from redthread.models import Endpoint, Finding, Severity

_SKIP_PARAMS = {"password", "passwd", "token", "csrf", "authenticity_token", "secret"}


class ReflectedXssCheck(Check):
    id = "reflected-xss"
    title = "Reflected cross-site scripting"
    severity = Severity.MEDIUM
    description = (
        "A request parameter is copied into an HTML response without encoding. "
        "The probe uses a harmless alert payload; the finding is based on the raw "
        "reflection, not on browser execution."
    )
    remediation = (
        "Encode untrusted values for the HTML context where they appear. A strict "
        "Content-Security-Policy with nonce-based script loading is useful defence in depth."
    )
    cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"

    def applies(self, endpoint: Endpoint) -> bool:
        return endpoint.method.upper() == "GET" and bool(params_for(endpoint))

    async def run(
        self, ctx: CheckContext, endpoint: Endpoint, identity: str | None = None
    ) -> list[Finding]:
        session = ctx.session(identity)
        baseline = await session.request("GET", endpoint.url)
        if not baseline.is_html or baseline.status >= 400:
            return []

        params = [
            name
            for name in params_for(endpoint)
            if name.lower() not in _SKIP_PARAMS and not name.lower().startswith("utm_")
        ]
        for name in params[:3]:
            marker = f"rt{secrets.token_hex(4)}"
            payload = f'"><svg/onload=alert("{marker}")>'
            url = replace_param(endpoint.url, name, payload)
            response = await session.request("GET", url)
            if response.status >= 400 or not response.is_html:
                continue
            if payload in response.text and payload not in baseline.text:
                index = response.text.find(payload)
                evidence = {
                    "parameter": name,
                    "payload": payload,
                    "status": response.status,
                    "context": clipped(
                        response.text[max(0, index - 160) : index + len(payload) + 160]
                    ),
                    "baseline_status": baseline.status,
                }
                return [
                    ctx.finding(
                        self,
                        endpoint,
                        parameter=name,
                        evidence=evidence,
                        confidence=0.85,
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
        response = await ctx.session(identity).request("GET", url)
        ok = response.is_html and response.status < 400 and payload in response.text
        evidence: dict[str, Any] = {
            "recheck_status": response.status,
            "payload": payload,
            "reflected": ok,
        }
        return ValidationResult(
            ok,
            0.85 if ok else 0.1,
            evidence,
            "the payload was sent again and the raw marker was checked in the HTML",
        )
