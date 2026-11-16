from __future__ import annotations

import json

import pytest

from redthread.audit import AuditLog
from redthread.budget import RunBudget
from redthread.errors import BudgetExceeded, ScopeError
from redthread.http import HttpSession
from redthread.ratelimit import RateLimiter
from redthread.scope import Scope
from tests.helpers import write_config


def _session(tmp_path, lab, *, max_requests=20, name="anonymous"):
    config = write_config(tmp_path / "redthread.toml", lab.base_url)
    scope = Scope(config)
    audit = AuditLog(tmp_path / f"{name}.jsonl", "test")
    budget = RunBudget(max_requests, 30)
    session = HttpSession(name, scope, RateLimiter(0), budget, audit)
    return session, audit, scope


async def test_scope_and_redirect_boundaries(tmp_path, lab):
    session, audit, _ = _session(tmp_path, lab)
    try:
        with pytest.raises(ScopeError):
            await session.request("GET", lab.base_url + "/logout")
        with pytest.raises(ScopeError):
            await session.request("GET", "https://example.com/")
        with pytest.raises(ScopeError):
            await session.request(
                "GET",
                lab.base_url + "/redirect",
                params={"next": "https://example.com/"},
                follow=True,
            )
    finally:
        await session.close()
        audit.close()


async def test_audit_redacts_sensitive_query_values(tmp_path, lab):
    session, audit, _ = _session(tmp_path, lab)
    try:
        response = await session.request(
            "GET",
            lab.base_url + "/login?username=alice&password=super-secret&token=abc",
        )
        assert response.status == 200

        records = [
            json.loads(line)
            for line in (tmp_path / "anonymous.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        request = next(item for item in records if item["event"] == "request")
        assert "super-secret" not in request["url"]
        assert "password=REDACTED" in request["url"]
        assert "token=REDACTED" in request["url"]
        assert "username=alice" in request["url"]
    finally:
        await session.close()
        audit.close()


async def test_request_budget_is_enforced(tmp_path, lab):
    session, audit, _ = _session(tmp_path, lab, max_requests=1)
    try:
        response = await session.request("GET", lab.base_url + "/")
        assert response.status == 200
        with pytest.raises(BudgetExceeded):
            await session.request("GET", lab.base_url + "/")
    finally:
        await session.close()
        audit.close()
