from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from redthread import __version__
from redthread.config import Config
from redthread.graph import Graph
from redthread.models import Finding, Severity, Status
from redthread.scope import redact_url

_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_SENSITIVE_EVIDENCE = {"authorization", "cookie", "set-cookie", "x-api-key"}


def _clean_evidence(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if key.lower() in _SENSITIVE_EVIDENCE:
                cleaned[key] = "REDACTED"
            elif key.lower() in ("url", "request_url", "endpoint") and isinstance(item, str):
                cleaned[key] = redact_url(item)
            else:
                cleaned[key] = _clean_evidence(item)
        return cleaned
    if isinstance(value, list):
        return [_clean_evidence(item) for item in value]
    return value


def _display(finding: Finding) -> dict[str, Any]:
    data = finding.to_dict()
    data["endpoint"] = redact_url(data["endpoint"])
    data["evidence"] = _clean_evidence(data.get("evidence") or {})
    return data


def _sort_key(finding: Finding) -> tuple[int, float, str]:
    return (-finding.severity.rank, -finding.cvss_score, finding.title)


def _json_block(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, default=str)


def _check_coverage(graph: Graph, findings: list[Finding]) -> list[dict[str, Any]]:
    stats = graph.action_stats()
    by_check: dict[str, dict[str, Any]] = {}
    for key, data in stats.items():
        check_id = key.split("|", 1)[0]
        if check_id == "request":
            continue
        bucket = by_check.setdefault(
            check_id, {"check": check_id, "actions": 0, "validated": 0, "rejected": 0}
        )
        bucket["actions"] += int(data.get("runs", 0))
    for finding in findings:
        if finding.check_id == "request":
            continue
        bucket = by_check.setdefault(
            finding.check_id,
            {"check": finding.check_id, "actions": 0, "validated": 0, "rejected": 0},
        )
        if finding.status == Status.VALIDATED:
            bucket["validated"] += 1
        elif finding.status == Status.REJECTED:
            bucket["rejected"] += 1
    return sorted(by_check.values(), key=lambda item: item["check"])


def build_report(
    graph: Graph,
    config: Config,
    *,
    run_id: str,
    run_dir: Path,
    started_at: str,
    finished_at: str,
    budget: dict[str, Any],
    scan: dict[str, Any],
    auth: list[dict[str, Any]],
    errors: list[str],
    llm_calls: int,
    stopped_reason: str,
) -> dict[str, Any]:
    findings = graph.findings()
    validated = sorted(
        (item for item in findings if item.status == Status.VALIDATED), key=_sort_key
    )
    rejected = sorted((item for item in findings if item.status == Status.REJECTED), key=_sort_key)
    unverified = sorted(
        (item for item in findings if item.status == Status.CANDIDATE), key=_sort_key
    )
    by_severity = {severity.value: 0 for severity in Severity}
    for finding in validated:
        by_severity[finding.severity.value] += 1
    display_ids = {finding.id: f"RT-{index:03d}" for index, finding in enumerate(validated, 1)}
    stats = graph.stats()
    duration = budget.get("elapsed_seconds", 0.0)
    return {
        "run": {
            "id": run_id,
            "engine": f"redthread {__version__}",
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_seconds": duration,
            "stopped_reason": stopped_reason,
            "config": config.redacted(),
        },
        "summary": {
            "validated": len(validated),
            "unverified": len(unverified),
            "rejected": len(rejected),
            "by_severity": by_severity,
            "requests": budget.get("requests", 0),
            "actions": sum(stats.get("actions", {}).values()),
            "llm_calls": llm_calls,
        },
        "scope": {
            "include": list(config.scope.include),
            "exclude": list(config.scope.exclude),
            "authorized": config.run.authorized,
            "allowed_methods": list(config.run.allowed_methods),
        },
        "identities": auth,
        "scan": scan,
        "coverage": _check_coverage(graph, findings),
        "findings": [{**_display(item), "display_id": display_ids[item.id]} for item in validated],
        "rejected": [
            {
                **_display(item),
                "validation_note": item.evidence.get("validation_note", ""),
            }
            for item in rejected
        ],
        "unverified": [
            {**_display(item), "note": "validation did not complete"} for item in unverified
        ],
        "errors": errors,
        "artifacts": {
            "graph": "graph.sqlite",
            "graph_json": "graph.json",
            "audit": "audit.jsonl",
            "markdown": "report.md",
            "sarif": "findings.sarif",
        },
    }


def write_reports(run_dir: Path, data: dict[str, Any], graph: Graph) -> dict[str, Path]:
    run_dir.mkdir(parents=True, exist_ok=True)
    findings_path = run_dir / "findings.json"
    findings_path.write_text(_json_block(data), encoding="utf-8")

    run_path = run_dir / "run.json"
    run_path.write_text(
        _json_block(
            {
                "run": data["run"],
                "summary": data["summary"],
                "scope": data["scope"],
                "errors": data["errors"],
            }
        ),
        encoding="utf-8",
    )

    markdown_path = run_dir / "report.md"
    markdown_path.write_text(_markdown(data), encoding="utf-8")

    sarif_path = run_dir / "findings.sarif"
    sarif_path.write_text(_sarif(data), encoding="utf-8")

    graph_path = run_dir / "graph.json"
    graph.export_json(graph_path)
    return {
        "findings": findings_path,
        "run": run_path,
        "report": markdown_path,
        "sarif": sarif_path,
        "graph": graph_path,
    }


def _markdown(data: dict[str, Any]) -> str:
    run = data["run"]
    summary = data["summary"]
    lines = [
        "# Exposure validation report",
        "",
        f"Run `{run['id']}` · {run['engine']}",
        "",
        f"Started {run['started_at']} and finished {run['finished_at']} "
        f"({run['duration_seconds']}s).",
        "",
        "## Summary",
        "",
    ]
    if summary["validated"]:
        severity_parts = [
            f"{count} {name}" for name, count in summary["by_severity"].items() if count
        ]
        lines.append(
            f"{summary['validated']} validated finding(s): " + ", ".join(severity_parts) + "."
        )
    else:
        lines.append("No validated findings were produced in this run.")
    lines.append(
        f"{summary['requests']} requests and {summary['actions']} actions were recorded. "
        f"{summary['rejected']} candidate(s) were rejected during replay; "
        f"{summary['unverified']} remain unverified."
    )
    if run.get("stopped_reason"):
        lines.append("")
        lines.append(f"**Run stopped early:** {run['stopped_reason']}.")
    lines.extend(["", "## Scope", ""])
    for item in data["scope"]["include"]:
        lines.append(f"- Included: `{item}`")
    for item in data["scope"]["exclude"]:
        lines.append(f"- Excluded: `{item}`")
    lines.append(f"- Methods: {', '.join(data['scope']['allowed_methods'])}")
    lines.append(
        "- Authorization flag: "
        + ("set" if data["scope"]["authorized"] else "not set (local targets only)")
    )
    if data["identities"]:
        lines.extend(["", "## Identities", ""])
        for identity in data["identities"]:
            state = "signed in" if identity.get("ok") else "failed"
            lines.append(
                f"- `{identity.get('name')}` ({identity.get('identity_kind')}): "
                f"{state}. {identity.get('detail', '')}"
            )

    lines.extend(["", "## Findings", ""])
    if not data["findings"]:
        lines.append("Nothing survived validation. See the rejected table below for context.")
    for finding in data["findings"]:
        lines.extend(
            [
                f"### {finding['display_id']} · {finding['title']}",
                "",
                f"**Severity:** {finding['severity']}  ",
                f"**Confidence:** {finding['confidence']}  ",
                f"**Endpoint:** `{finding['method']} {finding['endpoint']}`  ",
            ]
        )
        if finding.get("parameter"):
            lines.append(f"**Parameter:** `{finding['parameter']}`  ")
        if finding.get("cvss_score"):
            lines.append(f"**CVSS:** {finding['cvss_score']} (`{finding['cvss_vector']}`)  ")
        lines.extend(
            [
                "",
                finding.get("description", ""),
                "",
                "**Evidence**",
                "",
                "```json",
                _json_block(finding.get("evidence", {})),
                "```",
                "",
            ]
        )
        validation = finding.get("evidence", {}).get("validation_note")
        if validation:
            lines.extend([f"Validation: {validation}", ""])
        lines.extend(["**Remediation**", "", finding.get("remediation", ""), ""])

    if data["rejected"]:
        lines.extend(["## Rejected candidates", ""])
        lines.append(
            "These looked plausible on the first pass but did not survive a second "
            "request. They are kept here so the decision can be audited."
        )
        lines.append("")
        lines.append("| Check | Endpoint | Note |")
        lines.append("| --- | --- | --- |")
        for finding in data["rejected"]:
            note = finding.get("validation_note", "") or "replayed without the expected evidence"
            lines.append(
                f"| {finding['check_id']} | `{finding['method']} {finding['endpoint']}` | "
                f"{note.replace('|', '/')} |"
            )
        lines.append("")

    if data["unverified"]:
        lines.extend(["## Unverified candidates", ""])
        for finding in data["unverified"]:
            lines.append(f"- {finding['title']} at `{finding['method']} {finding['endpoint']}`")
        lines.append("")

    lines.extend(["## Coverage", ""])
    lines.append("| Check | Actions | Validated | Rejected |")
    lines.append("| --- | ---: | ---: | ---: |")
    for item in data["coverage"]:
        lines.append(
            f"| {item['check']} | {item['actions']} | {item['validated']} | {item['rejected']} |"
        )
    lines.append("")
    lines.extend(["## Run notes", ""])
    scan = data.get("scan", {})
    lines.append(
        f"Scanner fetched {scan.get('pages', 0)} page(s), recorded "
        f"{scan.get('endpoints', 0)} endpoint(s), and imported "
        f"{len(scan.get('specs', []))} API specification(s)."
    )
    if scan.get("graphql"):
        lines.append(f"GraphQL schema discovered at: {', '.join(scan['graphql'])}.")
    if data["errors"]:
        lines.append("")
        lines.append("Errors seen during the run:")
        lines.append("")
        for error in data["errors"][:20]:
            lines.append(f"- {error}")
    lines.extend(
        [
            "",
            "The checks are non-destructive and use GET/HEAD/OPTIONS only, plus POST "
            "for authentication and GraphQL introspection when explicitly enabled. "
            "Validated means the evidence was reproduced by a second request, not that "
            "the finding has been reviewed by a human.",
            "",
            "Artifacts: `findings.json`, `findings.sarif`, `graph.json`, `audit.jsonl`.",
            "",
        ]
    )
    return "\n".join(lines)


def _sarif(data: dict[str, Any]) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for finding in data["findings"]:
        rule_id = finding["check_id"]
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": finding["title"],
                "shortDescription": {"text": finding["title"]},
                "fullDescription": {"text": finding.get("description", "")},
                "help": {"text": finding.get("remediation", "")},
                "properties": {"severity": finding["severity"]},
            }
        path = urlsplit(finding["endpoint"]).path or "/"
        results.append(
            {
                "ruleId": rule_id,
                "level": _LEVEL.get(finding["severity"], "warning"),
                "message": {
                    "text": f"{finding['title']} at {finding['endpoint']}"
                    + (f" (parameter {finding['parameter']})" if finding.get("parameter") else "")
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": path},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "partialFingerprints": {"redthreadFinding": finding["id"]},
                "properties": {
                    "severity": finding["severity"],
                    "confidence": finding["confidence"],
                    "cvss": finding.get("cvss_score", 0.0),
                    "status": finding["status"],
                },
            }
        )
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "redthread",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": not data["run"].get("stopped_reason"),
                        "endTimeUtc": datetime.now(UTC).isoformat(timespec="seconds"),
                    }
                ],
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
