from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlunsplit

from redthread.models import Endpoint

_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def _example(schema: dict[str, Any] | None, name: str) -> str:
    schema = schema or {}
    for key in ("example", "default"):
        if key in schema and schema[key] is not None:
            return str(schema[key])
    enum = schema.get("enum")
    if enum:
        return str(enum[0])
    kind = schema.get("type", "string")
    if kind in ("integer", "number"):
        return "1"
    if kind == "boolean":
        return "true"
    if schema.get("format") == "uuid":
        return "00000000-0000-4000-8000-000000000001"
    if schema.get("format") == "date":
        return "2026-01-01"
    if name.lower().endswith("id"):
        return "1"
    return "sample"


def _server_url(spec: dict[str, Any], fallback: str) -> str:
    servers = spec.get("servers")
    if isinstance(servers, list) and servers:
        url = servers[0].get("url", "") if isinstance(servers[0], dict) else ""
        if url:
            return urljoin(fallback.rstrip("/") + "/", url.lstrip("/")).rstrip("/")
    if spec.get("swagger") == "2.0":
        host = spec.get("host", "")
        base_path = spec.get("basePath", "")
        schemes = spec.get("schemes") or ["http"]
        if host:
            return urlunsplit((schemes[0], host, base_path or "/", "", "")).rstrip("/")
    return fallback.rstrip("/")


def _query_params(operation: dict[str, Any], path_item: dict[str, Any]) -> dict[str, str]:
    params: list[Any] = []
    params.extend(path_item.get("parameters") or [])
    params.extend(operation.get("parameters") or [])
    query: dict[str, str] = {}
    for param in params:
        if not isinstance(param, dict) or not param.get("name"):
            continue
        if param.get("in") != "query":
            continue
        schema = param.get("schema") or param
        query[str(param["name"])] = _example(schema, str(param["name"]))
    return query


def parse_openapi(spec: dict[str, Any], base_url: str) -> list[Endpoint]:
    if not isinstance(spec, dict):
        return []
    if not any(key in spec for key in ("openapi", "swagger")):
        return []
    server = _server_url(spec, base_url)
    endpoints: list[Endpoint] = []
    for path, path_item in (spec.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method not in _METHODS or not isinstance(operation, dict):
                continue
            resolved_path = path
            params = list(path_item.get("parameters") or []) + list(
                operation.get("parameters") or []
            )
            for param in params:
                if not isinstance(param, dict) or param.get("in") != "path":
                    continue
                name = param.get("name")
                if not name:
                    continue
                value = _example(param.get("schema") or param, name)
                resolved_path = resolved_path.replace("{" + name + "}", value)
            query = _query_params(operation, path_item)
            url = urljoin(server + "/", resolved_path.lstrip("/"))
            tags = [str(tag) for tag in (operation.get("tags") or [])]
            fields: dict[str, str] = {}
            body = operation.get("requestBody") or {}
            if isinstance(body, dict):
                content = body.get("content") or {}
                for item in content.values():
                    if not isinstance(item, dict):
                        continue
                    schema = item.get("schema") or {}
                    for name in schema.get("properties") or {}:
                        fields[name] = _example((schema.get("properties") or {}).get(name), name)
            if not fields:
                for param in operation.get("parameters") or []:
                    if isinstance(param, dict) and param.get("in") == "formData":
                        fields[str(param.get("name"))] = _example(param, str(param.get("name")))
            endpoints.append(
                Endpoint(
                    method=method.upper(),
                    url=url,
                    params={**query, **fields},
                    source="openapi",
                    tags=tuple(sorted({"api", *tags})),
                    note=str(operation.get("summary") or ""),
                )
            )
    return endpoints
