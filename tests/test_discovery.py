from __future__ import annotations

from redthread.discovery import (
    is_dangerous,
    is_static_path,
    links_from_html,
    normalise_url,
)
from redthread.integrations.openapi import parse_openapi


def test_url_normalisation():
    assert normalise_url("http://host/a", "../b?z=2&a=1#frag") == "http://host/b?a=1&z=2"
    assert normalise_url("http://host/", "mailto:test@example.com") is None
    assert normalise_url("http://host/", "/static/app.js") is None
    assert normalise_url("http://host/", "javascript:alert(1)") is None


def test_static_and_dangerous_paths():
    assert is_static_path("/assets/logo.PNG")
    assert not is_static_path("/api/orders/1")
    assert is_dangerous("http://host/logout")
    assert is_dangerous("http://host/admin/delete/1")
    assert not is_dangerous("http://host/account")


def test_link_parser_includes_scripts_and_js_paths():
    html = """\
    <a href="/account">account</a>
    <a href="#skip">skip</a>
    <script src="/assets/app.js"></script>
    <script>const next = "/api/config";</script>
    """
    links = links_from_html(html)
    assert "/account" in links
    assert "/assets/app.js" in links
    assert "/api/config" in links


def test_openapi_paths_and_parameters():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "http://127.0.0.1:8000"}],
        "paths": {
            "/api/orders/{id}": {
                "get": {
                    "summary": "Read an order",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "schema": {"type": "integer"},
                        },
                        {
                            "name": "expand",
                            "in": "query",
                            "schema": {"type": "string", "example": "items"},
                        },
                    ],
                }
            },
            "/api/search": {
                "get": {"parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}]}
            },
        },
    }
    endpoints = parse_openapi(spec, "http://127.0.0.1:8000")
    by_path = {endpoint.path: endpoint for endpoint in endpoints}
    assert by_path["/api/orders/1"].params["expand"] == "items"
    assert by_path["/api/search"].params["q"] == "sample"
    assert all("api" in endpoint.tags for endpoint in endpoints)


def test_swagger_two_server():
    spec = {
        "swagger": "2.0",
        "host": "127.0.0.1:8000",
        "basePath": "/v1",
        "schemes": ["http"],
        "paths": {"/ping": {"get": {}}},
    }
    endpoints = parse_openapi(spec, "http://ignored.test")
    assert endpoints[0].url == "http://127.0.0.1:8000/v1/ping"
    assert endpoints[0].method == "GET"
