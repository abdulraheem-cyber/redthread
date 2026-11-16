from __future__ import annotations

import pytest

from redthread.cvss import cvss_score, severity_for_score
from redthread.models import Severity


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 4.3),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N", 4.7),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N", 7.7),
    ],
)
def test_cvss_vectors(vector, score):
    assert cvss_score(vector) == score


def test_invalid_vectors_score_zero():
    assert cvss_score("") == 0.0
    assert cvss_score("CVSS:3.1/AV:N/AC:L") == 0.0
    assert cvss_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 0.0


def test_severity_bands():
    assert severity_for_score(9.8) is Severity.CRITICAL
    assert severity_for_score(7.0) is Severity.HIGH
    assert severity_for_score(4.0) is Severity.MEDIUM
    assert severity_for_score(0.1) is Severity.LOW
    assert severity_for_score(0.0) is Severity.INFO
