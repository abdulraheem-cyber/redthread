from __future__ import annotations

from typing import Any

from redthread.checks.base import Check, CheckContext, ValidationResult
from redthread.models import Endpoint, Finding, Severity

_INTROSPECTION = (
    "query RedthreadSchema { __schema { queryType { name } "
    "mutationType { name } types { name kind } } }"
)


class GraphqlIntrospectionCheck(Check):
    id = "graphql-introspection"
    title = "GraphQL introspection is publicly available"
    severity = Severity.LOW
    description = (
        "The GraphQL endpoint answers an introspection query without authentication. "
        "This exposes the full schema and makes it easier to find hidden operations and "
        "input shapes. It is an information exposure issue, not an exploit by itself."
    )
    remediation = (
        "Disable introspection in production or require authentication for it. Apply "
        "query depth and cost limits as well."
    )

    def applies(self, endpoint: Endpoint) -> bool:
        return endpoint.method.upper() == "GET" and (
            "graphql" in endpoint.tags or endpoint.path.lower().endswith("/graphql")
        )

    def enabled(self, config, identities: list[str]) -> bool:
        return bool(config.run.allow_post)

    async def run(
        self, ctx: CheckContext, endpoint: Endpoint, identity: str | None = None
    ) -> list[Finding]:
        if not ctx.config.run.allow_post:
            return []
        session = ctx.session(identity)
        response = await session.request(
            "POST",
            endpoint.url,
            json={"query": _INTROSPECTION},
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        if response.status >= 400:
            return []
        try:
            payload = response.json()
        except ValueError:
            return []
        schema = (payload.get("data") or {}).get("__schema") if isinstance(payload, dict) else None
        if not isinstance(schema, dict):
            return []
        types = schema.get("types") or []
        if not types:
            return []
        names = [item.get("name") for item in types if isinstance(item, dict) and item.get("name")][
            :12
        ]
        evidence: dict[str, Any] = {
            "type_count": len(types),
            "query_type": (schema.get("queryType") or {}).get("name"),
            "mutation_type": (schema.get("mutationType") or {}).get("name"),
            "sample_types": names,
            "status": response.status,
        }
        return [
            ctx.finding(
                self,
                endpoint,
                evidence=evidence,
                confidence=0.95,
                identity=identity,
            )
        ]

    async def verify(self, ctx: CheckContext, finding: Finding) -> ValidationResult:
        identity = finding.discovered_by.rsplit(":", 1)[-1]
        identity = None if identity == "anonymous" else identity
        response = await ctx.session(identity).request(
            "POST",
            finding.endpoint,
            json={"query": _INTROSPECTION},
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        if response.status >= 400:
            return ValidationResult(False, 0.2, note=f"target returned {response.status}")
        try:
            schema = (response.json().get("data") or {}).get("__schema") or {}
        except (ValueError, AttributeError):
            return ValidationResult(False, 0.2, note="response was not JSON")
        types = schema.get("types") or []
        ok = bool(types)
        return ValidationResult(
            ok,
            0.95 if ok else 0.2,
            {"recheck_status": response.status, "type_count": len(types)},
            "introspection was requested a second time",
        )
