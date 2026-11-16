from __future__ import annotations

from redthread.checks import all_checks
from redthread.models import Endpoint
from redthread.planner import MctsPlanner, baseline_order, build_check_actions
from tests.helpers import write_config


def _fixture(tmp_path):
    config = write_config(tmp_path / "redthread.toml", "http://127.0.0.1:8000")
    endpoints = [
        Endpoint(
            "GET",
            "http://127.0.0.1:8000/api/orders/101",
            source="crawl",
            identities=("alice",),
            tags=("api",),
        ),
        Endpoint(
            "GET",
            "http://127.0.0.1:8000/search?q=books",
            params={"q": "books"},
            source="crawl",
            identities=("bob",),
            tags=("html",),
        ),
    ]
    return config, endpoints, all_checks()


def test_actions_are_deduplicated_per_origin_and_identity(tmp_path):
    config, endpoints, checks = _fixture(tmp_path)
    actions = build_check_actions(endpoints, checks, config, ["alice", "bob"], set())
    header_actions = [item for item in actions if item.check_id == "headers"]
    assert len(header_actions) == 1
    keys = [item.key for item in actions]
    assert len(keys) == len(set(keys))
    assert {item.check_id for item in actions} >= {
        "headers",
        "cors",
        "authz-object",
        "reflected-xss",
        "sql-injection",
    }


def test_executed_actions_are_not_offered_again(tmp_path):
    config, endpoints, checks = _fixture(tmp_path)
    actions = build_check_actions(endpoints, checks, config, ["alice", "bob"], set())
    first = actions[0]
    again = build_check_actions(endpoints, checks, config, ["alice", "bob"], {first.key})
    assert first.key not in {item.key for item in again}


def test_baseline_round_robin_starts_with_headers(tmp_path):
    config, endpoints, checks = _fixture(tmp_path)
    actions = build_check_actions(endpoints, checks, config, ["alice", "bob"], set())
    selected = baseline_order(actions, 4)
    assert len(selected) == 4
    assert selected[0].check_id == "headers"
    assert len({item.check_id for item in selected}) == len(selected)


def test_mcts_respects_executed_and_is_deterministic(tmp_path):
    config, endpoints, checks = _fixture(tmp_path)
    actions = build_check_actions(endpoints, checks, config, ["alice", "bob"], set())
    planner = MctsPlanner(checks, simulations=32, depth=3, seed=11)
    chosen = planner.choose(actions)
    assert chosen is not None
    assert chosen.key in {item.key for item in actions}

    executed = {item.key for item in actions}
    assert planner.choose(actions, executed) is None

    first = MctsPlanner(checks, simulations=32, depth=3, seed=5).choose(actions)
    second = MctsPlanner(checks, simulations=32, depth=3, seed=5).choose(actions)
    assert first is not None and second is not None
    assert first.key == second.key
