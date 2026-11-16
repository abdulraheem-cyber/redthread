from __future__ import annotations

import pytest

from redthread.config import load_config
from redthread.errors import ScopeError
from redthread.scope import Scope, redact_headers, redact_url


def _config(tmp_path, include: str, exclude: str = "", authorized: bool = True):
    path = tmp_path / "scope.toml"
    path.write_text(
        f"""\
[run]
authorized = {str(authorized).lower()}

[scope]
include = ["{include}"]
exclude = [{exclude}]
max_depth = 2
max_pages = 10
""",
        encoding="utf-8",
    )
    return load_config(path)


def test_path_prefix_and_methods(tmp_path):
    config = _config(tmp_path, "https://app.example.test/api")
    scope = Scope(config)
    scope.check("https://app.example.test/api/users", "GET")
    scope.check("https://app.example.test/api", "HEAD")
    with pytest.raises(ScopeError):
        scope.check("https://app.example.test/account", "GET")
    with pytest.raises(ScopeError):
        scope.check("https://app.example.test/api/users", "POST")


def test_wildcard_subdomain(tmp_path):
    config = _config(tmp_path, "https://*.example.test")
    scope = Scope(config)
    scope.check("https://one.example.test/", "GET")
    scope.check("https://deep.one.example.test/", "GET")
    with pytest.raises(ScopeError):
        scope.check("https://example.test/", "GET")
    with pytest.raises(ScopeError):
        scope.check("https://example.test.evil/", "GET")


def test_exclude_and_redirect_boundary(tmp_path):
    config = _config(tmp_path, "https://app.example.test", '"/admin/*"')
    scope = Scope(config)
    with pytest.raises(ScopeError):
        scope.check("https://app.example.test/admin/users", "GET")
    assert (
        scope.check_redirect("https://app.example.test/start", "/next")
        == "https://app.example.test/next"
    )
    with pytest.raises(ScopeError):
        scope.check_redirect("https://app.example.test/start", "https://other.test/x")


def test_remote_targets_need_authorization(tmp_path):
    blocked = Scope(_config(tmp_path, "https://app.example.test", authorized=False))
    with pytest.raises(ScopeError):
        blocked.require_authorization()

    local = Scope(_config(tmp_path, "http://127.0.0.1:8000", authorized=False))
    local.require_authorization()


def test_redaction_keeps_harmless_query_values():
    url = "http://127.0.0.1:8000/callback?code=abc123&q=books&token=secret"
    redacted = redact_url(url)
    assert "code=REDACTED" in redacted
    assert "token=REDACTED" in redacted
    assert "q=books" in redacted
    assert "secret" not in redacted
    headers = redact_headers({"Authorization": "Bearer x", "Accept": "text/html"})
    assert headers["Authorization"] == "REDACTED"
    assert headers["Accept"] == "text/html"
