from __future__ import annotations

import json

from redthread.graph import Graph
from redthread.models import Endpoint, Finding, Severity, Status, utcnow
from redthread.reporting import build_report, write_reports
from tests.helpers import write_config


def test_reports_include_validation_state_and_redaction(tmp_path):
    config = write_config(tmp_path / "redthread.toml", "http://127.0.0.1:8000")
    graph = Graph(tmp_path / "graph.sqlite")
    try:
        endpoint = Endpoint("GET", "http://127.0.0.1:8000/callback?token=secret-token&q=x")
        graph.upsert_endpoint(endpoint)

        validated = Finding(
            check_id="headers",
            title="Missing security headers",
            severity=Severity.LOW,
            method="GET",
            endpoint=endpoint.url,
            evidence={"url": endpoint.url},
            confidence=0.95,
        )
        graph.save_finding(validated)
        graph.update_finding(validated.id, Status.VALIDATED, confidence=0.95)

        rejected = Finding(
            check_id="reflected-xss",
            title="Reflected cross-site scripting",
            severity=Severity.MEDIUM,
            method="GET",
            endpoint="http://127.0.0.1:8000/search?q=x",
            parameter="q",
            evidence={"payload": "marker"},
        )
        graph.save_finding(rejected)
        graph.update_finding(
            rejected.id,
            Status.REJECTED,
            confidence=0.1,
            note="marker was no longer reflected",
        )

        graph.save_finding(
            Finding(
                check_id="sql-injection",
                title="SQL injection",
                severity=Severity.HIGH,
                method="GET",
                endpoint="http://127.0.0.1:8000/search?q=y",
                parameter="q",
            )
        )
        graph.record_action(
            "request|GET|http://127.0.0.1:8000/api/config",
            "explore",
            "no-result",
        )

        report = build_report(
            graph,
            config,
            run_id="2026-01-01_000000-test",
            run_dir=tmp_path,
            started_at=utcnow(),
            finished_at=utcnow(),
            budget={"requests": 10, "elapsed_seconds": 1.5},
            scan={"pages": 4, "endpoints": 4, "specs": [], "graphql": []},
            auth=[],
            errors=[],
            llm_calls=0,
            stopped_reason="",
        )
        artifacts = write_reports(tmp_path, report, graph)

        assert report["summary"]["validated"] == 1
        assert report["summary"]["rejected"] == 1
        assert report["summary"]["unverified"] == 1
        shown = report["findings"][0]
        assert "token=REDACTED" in shown["endpoint"]
        assert "secret-token" not in json.dumps(shown)
        assert "token=REDACTED" in shown["evidence"]["url"]
        assert report["rejected"][0]["validation_note"] == "marker was no longer reflected"
        assert {item["check"] for item in report["coverage"]} == {
            "headers",
            "reflected-xss",
            "sql-injection",
        }

        findings_json = json.loads(artifacts["findings"].read_text(encoding="utf-8"))
        assert "secret-token" not in json.dumps(findings_json)
        run_json = json.loads(artifacts["run"].read_text(encoding="utf-8"))
        assert run_json["summary"]["requests"] == 10

        markdown = artifacts["report"].read_text(encoding="utf-8")
        assert "RT-001" in markdown
        assert "Rejected candidates" in markdown
        assert "marker was no longer reflected" in markdown

        sarif_text = artifacts["sarif"].read_text(encoding="utf-8")
        sarif = json.loads(sarif_text)
        assert "github.com/redthread" not in sarif_text
        assert sarif["runs"][0]["results"][0]["ruleId"] == "headers"
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "redthread"

        graph_json = json.loads(artifacts["graph"].read_text(encoding="utf-8"))
        assert graph_json["findings"]
        assert graph_json["exported_at"]
    finally:
        graph.close()
