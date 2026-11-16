from __future__ import annotations

import json

from redthread.graph import Graph
from redthread.models import Endpoint, Finding, Severity, Status


def test_endpoint_merge_and_edges(tmp_path):
    graph = Graph(tmp_path / "graph.sqlite")
    try:
        graph.upsert_endpoint(
            Endpoint(
                "GET",
                "http://127.0.0.1:8000/api/orders/101",
                source="crawl",
                identities=("alice",),
                tags=("api",),
            )
        )
        graph.upsert_endpoint(
            Endpoint(
                "GET",
                "http://127.0.0.1:8000/api/orders/101",
                params={"expand": "items"},
                source="openapi",
                identities=("bob",),
                tags=("json",),
            )
        )
        endpoints = graph.endpoints()
        assert len(endpoints) == 1
        assert endpoints[0].identities == ("alice", "bob")
        assert endpoints[0].params == {"expand": "items"}
        assert endpoints[0].tags == ("api", "json")
        assert graph.count_nodes("identity") == 2
        node = graph.get_node("endpoint", "GET http://127.0.0.1:8000/api/orders/101")
        assert node and node["props"]["source"] == "openapi"
    finally:
        graph.close()


def test_finding_status_never_regresses(tmp_path):
    graph = Graph(tmp_path / "graph.sqlite")
    try:
        finding = Finding(
            check_id="sql-injection",
            title="SQL injection",
            severity=Severity.HIGH,
            method="GET",
            endpoint="http://127.0.0.1:8000/search?q=x",
            parameter="q",
            evidence={"first": True},
        )
        graph.save_finding(finding)
        assert graph.findings(Status.CANDIDATE)

        graph.upsert_endpoint(Endpoint("GET", "http://127.0.0.1:8000/search?q=x"))

        graph.update_finding(finding.id, Status.VALIDATED, confidence=0.9)
        graph.save_finding(
            Finding(
                check_id=finding.check_id,
                title=finding.title,
                severity=finding.severity,
                method=finding.method,
                endpoint=finding.endpoint,
                parameter=finding.parameter,
            )
        )
        current = graph.get_finding(finding.id)
        assert current is not None
        assert current.status is Status.VALIDATED
        assert current.confidence == 0.9
        assert current.verified_at

        export = graph.export_json(tmp_path / "graph.json")
        payload = json.loads(export.read_text(encoding="utf-8"))
        assert payload["findings"][0]["status"] == "validated"
        assert payload["nodes"]
    finally:
        graph.close()


def test_finding_identity_is_stable():
    first = Finding(
        check_id="reflected-xss",
        title="XSS",
        severity=Severity.MEDIUM,
        method="get",
        endpoint="http://host/x",
        parameter="q",
    )
    second = Finding(
        check_id="reflected-xss",
        title="XSS",
        severity=Severity.MEDIUM,
        method="GET",
        endpoint="http://host/x",
        parameter="q",
    )
    assert first.id == second.id
