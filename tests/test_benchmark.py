from __future__ import annotations

import json

import pytest

from redthread.benchmark import evaluate_run, load_truth
from redthread.cli import main
from redthread.errors import BenchmarkError


def _run_dir(tmp_path, findings):
    run = tmp_path / "run"
    run.mkdir()
    (run / "findings.json").write_text(
        json.dumps({"run": {"id": "run-1"}, "findings": findings}),
        encoding="utf-8",
    )
    return run


def _truth(tmp_path):
    path = tmp_path / "truth.json"
    path.write_text(
        json.dumps(
            {
                "name": "unit",
                "findings": [
                    {"check_id": "headers"},
                    {"check_id": "reflected-xss", "path": "/products", "parameter": "category"},
                    {"check_id": "sql-injection", "path": "/search", "parameter": "q"},
                ],
            }
        ),
        encoding="utf-8",
    )
    return load_truth(path)


def test_evaluate_counts_missing_and_unexpected(tmp_path):
    run = _run_dir(
        tmp_path,
        [
            {"check_id": "headers", "endpoint": "http://host/api/config", "parameter": None},
            {
                "check_id": "reflected-xss",
                "endpoint": "http://host/products?category=x",
                "parameter": "category",
            },
            {"check_id": "cors", "endpoint": "http://host/api/config", "parameter": None},
        ],
    )
    result = evaluate_run(run, _truth(tmp_path))
    assert result["expected"] == 3
    assert result["satisfied"] == 2
    assert result["false_negatives"] == 1
    assert result["false_positives"] == 1
    assert result["precision"] == 0.667
    assert result["recall"] == 0.667
    assert result["missing"][0]["check_id"] == "sql-injection"
    assert result["unexpected"][0]["check_id"] == "cors"


def test_path_and_parameter_have_to_match(tmp_path):
    run = _run_dir(
        tmp_path,
        [
            {
                "check_id": "reflected-xss",
                "endpoint": "http://host/search?q=x",
                "parameter": "q",
            }
        ],
    )
    result = evaluate_run(run, _truth(tmp_path))
    assert result["satisfied"] == 0
    assert result["unexpected"][0]["check_id"] == "reflected-xss"


def test_invalid_truth_is_rejected(tmp_path):
    path = tmp_path / "empty.json"
    path.write_text('{"findings": []}', encoding="utf-8")
    with pytest.raises(BenchmarkError):
        load_truth(path)


def test_eval_cli(tmp_path, capsys):
    run = _run_dir(
        tmp_path,
        [
            {
                "check_id": "reflected-xss",
                "endpoint": "http://host/products?category=x",
                "parameter": "category",
            }
        ],
    )
    truth = tmp_path / "truth.json"
    truth.write_text(
        json.dumps(
            {
                "name": "cli",
                "findings": [
                    {
                        "check_id": "reflected-xss",
                        "path": "/products",
                        "parameter": "category",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert main(["eval", "--run", str(run), "--truth", str(truth), "--json"]) == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["recall"] == 1.0

    missing_truth = tmp_path / "missing.json"
    missing_truth.write_text(
        json.dumps({"name": "cli", "findings": [{"check_id": "sql-injection"}]}),
        encoding="utf-8",
    )
    assert (
        main(
            [
                "eval",
                "--run",
                str(run),
                "--truth",
                str(missing_truth),
                "--strict",
            ]
        )
        == 1
    )
