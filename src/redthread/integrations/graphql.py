from __future__ import annotations

from typing import Any


def schema_fields(payload: dict[str, Any]) -> dict[str, list[str]]:
    """Pull query and mutation field names out of an introspection response."""
    schema = ((payload or {}).get("data") or {}).get("__schema") or {}
    if not isinstance(schema, dict):
        return {}
    types = schema.get("types") or []

    def fields_for(type_name: str | None) -> list[str]:
        if not type_name:
            return []
        for item in types:
            if isinstance(item, dict) and item.get("name") == type_name:
                return sorted(
                    str(field.get("name"))
                    for field in (item.get("fields") or [])
                    if isinstance(field, dict) and field.get("name")
                )
        return []

    query_type = (schema.get("queryType") or {}).get("name")
    mutation_type = (schema.get("mutationType") or {}).get("name")
    result: dict[str, list[str]] = {}
    if query_type:
        result["query"] = fields_for(query_type)
    if mutation_type:
        result["mutation"] = fields_for(mutation_type)
    return result


INTROSPECTION_QUERY = (
    "query RedthreadSchema { __schema { queryType { name } mutationType { name } "
    "types { name kind fields { name } } } }"
)
