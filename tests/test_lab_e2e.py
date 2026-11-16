from __future__ import annotations

import asyncio
import json

import pytest

from redthread.models import Status
from redthread.orchestrator import Orchestrator
from tests.helpers import write_config

EXPECTED_CHECKS = {
    "headers",
    "cors",
    "open-redirect",
    "reflected-xss",
    "sql-injection",
    "graphql-introspection",
    "authz-object",
}


@pytest.fixture(scope="session")
def lab_run(lab, tmp_path_factory):
    work = tmp_path_factory.mktemp("lab-run")
    config = write_config(work / "redthread.toml", lab.base_url)
    return asyncio.run(Orchestrator(config).run())


def test_end_to_end_finds_and_validates_lab_issues(lab_run):
    report = lab_run.report
    findings = report["findings"]
    assert {item["check_id"] for item in findings} == EXPECTED_CHECKS

    for finding in findings:
        assert finding["status"] == Status.VALIDATED.value
        assert finding["confidence"] > 0.5
        assert finding["verified_at"]
        assert finding["endpoint"].startswith("http://127.0.0.1:")

    identities = {item["name"]: item for item in report["identities"]}
    assert identities["alice"]["ok"] is True
    assert identities["bob"]["ok"] is True

    by_check = {item["check_id"]: item for item in findings}
    assert by_check["sql-injection"]["evidence"]["technique"] == "error-based"
    assert by_check["reflected-xss"]["parameter"] == "category"
    assert by_check["open-redirect"]["parameter"] == "next"
    assert by_check["cors"]["evidence"]["access-control-allow-credentials"] == "true"
    assert by_check["authz-object"]["evidence"]["attacker"] in ("alice", "bob")
    assert by_check["authz-object"]["evidence"]["anonymous_status"] == 401
    assert by_check["graphql-introspection"]["evidence"]["type_count"] >= 1
    assert by_check["headers"]["evidence"]["missing"]


def test_end_to_end_writes_artifacts_without_credentials(lab_run):
    for name in ("findings.json", "run.json", "report.md", "findings.sarif", "graph.json"):
        path = lab_run.run_dir / name
        assert path.exists() and path.stat().st_size > 0, name

    combined = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in (
            lab_run.run_dir / "findings.json",
            lab_run.run_dir / "run.json",
            lab_run.run_dir / "report.md",
            lab_run.run_dir / "audit.jsonl",
        )
    )
    assert "alice-pw" not in combined
    assert "bob-pw" not in combined

    findings = json.loads((lab_run.run_dir / "findings.json").read_text(encoding="utf-8"))
    assert findings["summary"]["validated"] == len(findings["findings"])
    assert findings["summary"]["requests"] > 10
    assert findings["run"]["engine"].startswith("redthread")

    audit_lines = (lab_run.run_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(audit_lines) > 10
    for line in audit_lines:
        record = json.loads(line)
        assert record["run"] == lab_run.run_dir.name
        assert record["event"]

    sarif = json.loads((lab_run.run_dir / "findings.sarif").read_text(encoding="utf-8"))
    assert len(sarif["runs"][0]["results"]) == len(findings["findings"])


def test_end_to_end_rejected_candidates_are_kept(lab_run):
    report = lab_run.report
    assert report["summary"]["rejected"] >= 0
    for item in report["rejected"]:
        assert item["status"] == Status.REJECTED.value
        assert item["validation_note"] or item["evidence"].get("validation_note")
