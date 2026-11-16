from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from redthread.errors import BenchmarkError


@dataclass(frozen=True)
class Expectation:
    check_id: str
    parameter: str | None = None
    path: str = ""
    path_contains: str = ""
    min_count: int = 1
    note: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Expectation:
        check_id = str(data.get("check_id", "")).strip()
        if not check_id:
            raise BenchmarkError("every expectation needs a check_id")
        parameter = data.get("parameter")
        return cls(
            check_id=check_id,
            parameter=str(parameter) if parameter is not None else None,
            path=str(data.get("path", "")),
            path_contains=str(data.get("path_contains", "")),
            min_count=max(1, int(data.get("min_count", 1))),
            note=str(data.get("note", "")),
        )

    def matches(self, finding: dict[str, Any]) -> bool:
        if str(finding.get("check_id", "")) != self.check_id:
            return False
        if self.parameter is not None and finding.get("parameter") != self.parameter:
            return False
        path = urlsplit(str(finding.get("endpoint", ""))).path or "/"
        if self.path and path != self.path:
            return False
        if self.path_contains and self.path_contains not in path:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "parameter": self.parameter,
            "path": self.path,
            "path_contains": self.path_contains,
            "min_count": self.min_count,
            "note": self.note,
        }


@dataclass(frozen=True)
class Truth:
    name: str
    expectations: tuple[Expectation, ...]
    source: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any], source: str = "") -> Truth:
        raw = data.get("findings", data.get("expected", []))
        if not isinstance(raw, list):
            raise BenchmarkError("truth file needs a findings array")
        expectations = tuple(Expectation.from_dict(item) for item in raw if isinstance(item, dict))
        if not expectations:
            raise BenchmarkError("truth file has no expectations")
        return cls(name=str(data.get("name", "")), expectations=expectations, source=source)


def load_truth(path: str | Path) -> Truth:
    target = Path(path)
    if not target.exists():
        raise BenchmarkError(f"truth file not found: {target}")
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkError(f"could not read {target}: {exc}") from exc
    if not isinstance(data, dict):
        raise BenchmarkError("truth file must contain a JSON object")
    return Truth.from_dict(data, str(target))


def load_findings(run_dir: str | Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    directory = Path(run_dir)
    path = directory / "findings.json"
    if not path.exists():
        raise BenchmarkError(f"findings.json not found in {directory}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkError(f"could not read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise BenchmarkError("findings.json must contain a JSON object")
    findings = data.get("findings", [])
    if not isinstance(findings, list):
        raise BenchmarkError("findings.json does not contain a findings array")
    return data, [item for item in findings if isinstance(item, dict)]


def evaluate_run(run_dir: str | Path, truth: Truth) -> dict[str, Any]:
    data, findings = load_findings(run_dir)
    counts = [0 for _ in truth.expectations]
    true_positives = 0
    unexpected: list[dict[str, Any]] = []

    for finding in findings:
        index = next(
            (
                position
                for position, expectation in enumerate(truth.expectations)
                if expectation.matches(finding)
            ),
            None,
        )
        if index is None:
            unexpected.append(
                {
                    "check_id": finding.get("check_id", ""),
                    "severity": finding.get("severity", ""),
                    "endpoint": finding.get("endpoint", ""),
                    "parameter": finding.get("parameter"),
                }
            )
            continue
        counts[index] += 1
        true_positives += 1

    satisfied = [
        expectation
        for expectation, count in zip(truth.expectations, counts, strict=True)
        if count >= expectation.min_count
    ]
    missing = [
        {**expectation.to_dict(), "observed": count}
        for expectation, count in zip(truth.expectations, counts, strict=True)
        if count < expectation.min_count
    ]

    expected_total = len(truth.expectations)
    precision = (
        true_positives / (true_positives + len(unexpected))
        if true_positives + len(unexpected)
        else 0.0
    )
    recall = len(satisfied) / expected_total if expected_total else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    by_check: dict[str, dict[str, int]] = {}
    for expectation, count in zip(truth.expectations, counts, strict=True):
        bucket = by_check.setdefault(expectation.check_id, {"expected": 0, "satisfied": 0})
        bucket["expected"] += 1
        if count >= expectation.min_count:
            bucket["satisfied"] += 1

    return {
        "suite": truth.name,
        "run": data.get("run", {}).get("id", Path(run_dir).name),
        "expected": expected_total,
        "satisfied": len(satisfied),
        "true_positives": true_positives,
        "false_positives": len(unexpected),
        "false_negatives": len(missing),
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "by_check": dict(sorted(by_check.items())),
        "missing": missing,
        "unexpected": unexpected,
    }
