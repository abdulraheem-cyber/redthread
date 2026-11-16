from __future__ import annotations

from redthread.audit import AuditLog
from redthread.budget import RunBudget
from redthread.checks import CheckContext, all_checks
from redthread.graph import Graph
from redthread.http import HttpSession
from redthread.models import Endpoint, Status
from redthread.ratelimit import RateLimiter
from redthread.scope import Scope
from tests.helpers import write_config


async def test_checks_and_replay_validation(tmp_path, lab):
    config = write_config(
        tmp_path / "redthread.toml",
        lab.base_url,
        allow_post=False,
    )
    scope = Scope(config)
    graph = Graph(tmp_path / "graph.sqlite")
    audit = AuditLog(tmp_path / "audit.jsonl", "test")
    session = HttpSession("anonymous", scope, RateLimiter(0), RunBudget(80, 60), audit)
    ctx = CheckContext(
        config=config,
        graph=graph,
        scope=scope,
        sessions={},
        anonymous=session,
        audit=audit,
    )
    checks = all_checks()
    cases = [
        (
            "headers",
            Endpoint("GET", lab.base_url + "/"),
        ),
        (
            "cors",
            Endpoint("GET", lab.base_url + "/api/config", tags=("api",)),
        ),
        (
            "open-redirect",
            Endpoint(
                "GET",
                lab.base_url + "/redirect?next=/account",
                params={"next": "/account"},
            ),
        ),
        (
            "reflected-xss",
            Endpoint(
                "GET",
                lab.base_url + "/products?category=books",
                params={"category": "books"},
            ),
        ),
        (
            "sql-injection",
            Endpoint(
                "GET",
                lab.base_url + "/search?q=books",
                params={"q": "books"},
            ),
        ),
    ]
    try:
        for check_id, endpoint in cases:
            check = checks[check_id]
            assert check.applies(endpoint)
            findings = await check.run(ctx, endpoint)
            assert findings, check_id
            verdict = await check.verify(ctx, findings[0])
            assert verdict.ok, (check_id, verdict.note, verdict.evidence)
            assert verdict.confidence > 0.5
            findings[0].status = Status.VALIDATED
            graph.save_finding(findings[0])

        assert {item.check_id for item in graph.findings()} == {check_id for check_id, _ in cases}
    finally:
        await session.close()
        audit.close()
        graph.close()
