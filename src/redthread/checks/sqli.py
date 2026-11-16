from __future__ import annotations

import re
from typing import Any

from redthread.checks.base import (
    Check,
    CheckContext,
    ValidationResult,
    body_similarity,
    clipped,
    is_success,
    params_for,
    replace_param,
)
from redthread.models import Endpoint, Finding, Severity

_SKIP_PARAMS = {"password", "passwd", "token", "csrf", "authenticity_token", "secret", "email"}

_ERROR_SIGNATURES = (
    "you have an error in your sql syntax",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlite3.operationalerror",
    "sqlite error",
    "sqlstate[",
    "pg_query",
    "postgresql",
    "ora-01756",
    "ora-00933",
    "mysqlsyntaxerror",
    "syntax error at or near",
    "warning: mysql",
    "odbc sql server driver",
    "microsoft sql native client",
)

_DYNAMIC = re.compile(
    r"(?i)(nonce|csrf|token|request[_-]?id|timestamp|date)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9._:-]{6,}"
)


def _normalised(text: str) -> str:
    return re.sub(r"\s+", " ", _DYNAMIC.sub("", text)).strip().lower()


def _error_hit(text: str) -> str:
    lower = text.lower()
    for signature in _ERROR_SIGNATURES:
        if signature in lower:
            return signature
    return ""


class SqlInjectionCheck(Check):
    id = "sql-injection"
    title = "SQL injection"
    severity = Severity.HIGH
    description = (
        "An input changes the structure of a backend SQL query. The check first "
        "looks for database error text, then for a stable boolean difference between "
        "a true and false condition. No write statements are sent."
    )
    remediation = (
        "Use parameterised queries or an ORM that binds values. Avoid concatenating "
        "request data into SQL, and do not return database errors to clients."
    )
    cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"

    def applies(self, endpoint: Endpoint) -> bool:
        return endpoint.method.upper() == "GET" and bool(params_for(endpoint))

    async def run(
        self, ctx: CheckContext, endpoint: Endpoint, identity: str | None = None
    ) -> list[Finding]:
        session = ctx.session(identity)
        baseline = await session.request("GET", endpoint.url)
        if baseline.status >= 500:
            return []
        baseline_text = baseline.text
        params = [
            name
            for name in params_for(endpoint)
            if name.lower() not in _SKIP_PARAMS and not name.lower().startswith("utm_")
        ]
        if not params:
            return []

        for name in params[:2]:
            original = params_for(endpoint).get(name, "1")
            for quote in ("'", '"'):
                payload = original + quote
                url = replace_param(endpoint.url, name, payload)
                response = await session.request("GET", url)
                hit = _error_hit(response.text)
                if hit and hit not in baseline_text.lower():
                    evidence = {
                        "parameter": name,
                        "payload": payload,
                        "technique": "error-based",
                        "signature": hit,
                        "status": response.status,
                        "baseline_status": baseline.status,
                        "body_excerpt": clipped(response.text, 600),
                    }
                    return [
                        ctx.finding(
                            self,
                            endpoint,
                            parameter=name,
                            evidence=evidence,
                            confidence=0.9,
                            identity=identity,
                        )
                    ]

            true_value = original + "' AND '1'='1"
            false_value = original + "' AND '1'='2"
            true_response = await session.request(
                "GET", replace_param(endpoint.url, name, true_value)
            )
            false_response = await session.request(
                "GET", replace_param(endpoint.url, name, false_value)
            )
            if not (
                is_success(baseline.status)
                and is_success(true_response.status)
                and true_response.status == baseline.status
            ):
                continue
            similarity_true = body_similarity(
                _normalised(baseline_text), _normalised(true_response.text)
            )
            similarity_false = body_similarity(
                _normalised(true_response.text), _normalised(false_response.text)
            )
            size_gap = abs(len(true_response.text) - len(false_response.text))
            if similarity_true >= 0.97 and similarity_false <= 0.92 and size_gap > 20:
                evidence = {
                    "parameter": name,
                    "payload_true": true_value,
                    "payload_false": false_value,
                    "technique": "boolean-differential",
                    "similarity_baseline_true": round(similarity_true, 3),
                    "similarity_true_false": round(similarity_false, 3),
                    "size_gap": size_gap,
                    "body_excerpt": clipped(false_response.text, 400),
                }
                return [
                    ctx.finding(
                        self,
                        endpoint,
                        parameter=name,
                        evidence=evidence,
                        confidence=0.72,
                        identity=identity,
                    )
                ]
        return []

    async def verify(self, ctx: CheckContext, finding: Finding) -> ValidationResult:
        parameter = finding.parameter or ""
        technique = finding.evidence.get("technique", "")
        identity = finding.discovered_by.rsplit(":", 1)[-1]
        identity = None if identity == "anonymous" else identity
        session = ctx.session(identity)

        if technique == "error-based":
            payload = finding.evidence.get("payload", "")
            signature = finding.evidence.get("signature", "")
            if not payload:
                return ValidationResult(False, 0.0, note="payload was missing")
            response = await session.request(
                "GET", replace_param(finding.endpoint, parameter, payload)
            )
            ok = bool(signature) and signature in response.text.lower()
            return ValidationResult(
                ok,
                0.9 if ok else 0.1,
                {"recheck_status": response.status, "signature": signature},
                "the error payload was replayed and the database signature checked",
            )

        if technique == "boolean-differential":
            true_payload = finding.evidence.get("payload_true", "")
            false_payload = finding.evidence.get("payload_false", "")
            if not true_payload or not false_payload:
                return ValidationResult(False, 0.0, note="payloads were missing")
            baseline = await session.request("GET", finding.endpoint)
            true_response = await session.request(
                "GET", replace_param(finding.endpoint, parameter, true_payload)
            )
            false_response = await session.request(
                "GET", replace_param(finding.endpoint, parameter, false_payload)
            )
            similarity_true = body_similarity(
                _normalised(baseline.text), _normalised(true_response.text)
            )
            similarity_false = body_similarity(
                _normalised(true_response.text), _normalised(false_response.text)
            )
            gap = abs(len(true_response.text) - len(false_response.text))
            ok = similarity_true >= 0.95 and similarity_false <= 0.94 and gap > 15
            evidence: dict[str, Any] = {
                "recheck_status": true_response.status,
                "similarity_baseline_true": round(similarity_true, 3),
                "similarity_true_false": round(similarity_false, 3),
                "size_gap": gap,
            }
            return ValidationResult(
                ok,
                0.7 if ok else 0.1,
                evidence,
                "the true/false pair was replayed and compared again",
            )

        return ValidationResult(False, 0.0, note="unknown SQL injection technique")
