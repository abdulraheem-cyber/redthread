from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    return math.ceil(round(value, 6) * 10) / 10


def cvss_score(vector: str) -> float:
    """Return the CVSS v3.1 base score for a vector string.

    Only the base metrics are accepted. Temporal and environmental metrics
    are ignored, which is what the report needs.
    """
    if not vector:
        return 0.0
    parts = vector.split("/")
    if parts and parts[0].startswith("CVSS:3"):
        parts = parts[1:]
    metrics: dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        metrics[key.upper()] = value.upper()
    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if any(key not in metrics for key in required):
        return 0.0
    try:
        changed = metrics["S"] == "C"
        pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[metrics["PR"]]
        confidentiality = _CIA[metrics["C"]]
        integrity = _CIA[metrics["I"]]
        availability = _CIA[metrics["A"]]
        iss = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))
        if changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss
        exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr * _UI[metrics["UI"]]
    except KeyError:
        return 0.0
    if impact <= 0:
        return 0.0
    if changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def severity_for_score(score: float):
    from redthread.models import Severity

    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO
