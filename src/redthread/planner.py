from __future__ import annotations

import math
import random
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from redthread.checks import Check
from redthread.config import Config
from redthread.models import Endpoint, Severity


@dataclass(frozen=True)
class ActionCandidate:
    key: str
    kind: str
    label: str
    prior: float
    endpoint: Endpoint | None = None
    check_id: str = ""
    identity: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    tags: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "kind": self.kind,
            "label": self.label,
            "check_id": self.check_id,
            "identity": self.identity,
            "endpoint": self.endpoint.url if self.endpoint else "",
            "prior": round(self.prior, 3),
            "tags": list(self.tags),
        }


def _endpoint_interest(endpoint: Endpoint) -> float:
    score = float(len(endpoint.params)) * 2.0
    if "api" in endpoint.tags:
        score += 6.0
    if "graphql" in endpoint.tags:
        score += 2.0
    if "form" in endpoint.tags:
        score += 2.0
    if endpoint.method.upper() == "POST":
        score -= 3.0
    if endpoint.path.count("/") > 5:
        score -= 1.0
    return score


def _preferred_identity(endpoint: Endpoint, identities: list[str]) -> str:
    for name in endpoint.identities:
        if name in identities:
            return name
    return identities[0] if identities else "anonymous"


def build_check_actions(
    endpoints: Iterable[Endpoint],
    checks: dict[str, Check],
    config: Config,
    identities: list[str],
    executed: set[str],
) -> list[ActionCandidate]:
    actions: dict[str, ActionCandidate] = {}
    for endpoint in endpoints:
        for check in checks.values():
            if not check.enabled(config, identities):
                continue
            if check.id == "authz-object" and not endpoint.identities:
                continue
            if not check.applies(endpoint):
                continue
            identity = _preferred_identity(endpoint, identities)
            key = check.action_key(endpoint, identity)
            if key in executed or key in actions:
                continue
            prior = 0.1 + check.severity.weight * 0.5
            if "api" in endpoint.tags:
                prior += 0.08
            if endpoint.params:
                prior += 0.08
            actions[key] = ActionCandidate(
                key=key,
                kind="check",
                label=f"{check.id} on {endpoint.method} {endpoint.path}",
                prior=min(1.0, prior),
                endpoint=endpoint,
                check_id=check.id,
                identity=identity,
                tags=endpoint.tags,
            )
    return sorted(actions.values(), key=lambda item: (-item.prior, item.key))


def baseline_order(actions: list[ActionCandidate], limit: int) -> list[ActionCandidate]:
    """Take a round-robin slice across checks so one noisy check cannot eat the budget."""
    if limit <= 0:
        return []
    groups: dict[str, list[ActionCandidate]] = {}
    for action in actions:
        groups.setdefault(action.check_id, []).append(action)
    for group in groups.values():
        group.sort(key=lambda item: -_endpoint_interest(item.endpoint) if item.endpoint else 0)
    order = list(groups)
    order.sort(key=lambda check_id: (check_id != "headers", check_id))
    picked: list[ActionCandidate] = []
    while len(picked) < limit and any(groups.values()):
        for check_id in order:
            group = groups[check_id]
            if not group:
                continue
            picked.append(group.pop(0))
            if len(picked) >= limit:
                break
    return picked


class OutcomeModel:
    """Small Beta-ish model of whether an action will produce a finding.

    Priors come from check severity. Observed outcomes from the graph nudge the
    estimate. This is deliberately simple; the planner should not pretend to
    know more than the run has taught it.
    """

    def __init__(
        self,
        checks: dict[str, Check],
        stats: dict[str, dict[str, float]] | None = None,
    ):
        self.checks = checks
        self.stats = stats or {}
        self._observed: dict[str, list[float]] = {}

    def observe(self, check_id: str, success: bool) -> None:
        if not check_id:
            return
        counts = self._observed.setdefault(check_id, [0.0, 0.0])
        counts[0] += 1
        if success:
            counts[1] += 1

    def probability(self, action: ActionCandidate) -> float:
        if action.kind == "request":
            return 0.28
        check = self.checks.get(action.check_id)
        weight = check.severity.weight if check else 0.5
        base = 0.08 + 0.24 * weight
        runs = 0.0
        wins = 0.0
        prefix = action.check_id + "|"
        for key, stat in self.stats.items():
            if key.startswith(prefix):
                runs += stat.get("runs", 0)
                wins += stat.get("wins", 0)
        observed = self._observed.get(action.check_id)
        if observed:
            runs += observed[0]
            wins += observed[1]
        if runs:
            return (wins + 4 * base) / (runs + 4)
        return base

    def reward(self, action: ActionCandidate) -> float:
        check = self.checks.get(action.check_id)
        weight = check.severity.weight if check else 0.4
        if action.kind == "request":
            weight = 0.35
        if self.probability(action) <= 0:
            return 0.0
        return 0.35 + 0.65 * weight


class _Node:
    __slots__ = ("action", "parent", "children", "untried", "visits", "value")

    def __init__(
        self,
        action: ActionCandidate | None = None,
        parent: _Node | None = None,
        untried: list[ActionCandidate] | None = None,
    ):
        self.action = action
        self.parent = parent
        self.children: dict[str, _Node] = {}
        self.untried = untried or []
        self.visits = 0
        self.value = 0.0


class MctsPlanner:
    def __init__(
        self,
        checks: dict[str, Check],
        stats: dict[str, dict[str, float]] | None = None,
        *,
        simulations: int = 72,
        depth: int = 3,
        exploration: float = 1.2,
        seed: int = 7,
    ):
        self.model = OutcomeModel(checks, stats)
        self.simulations = simulations
        self.depth = depth
        self.exploration = exploration
        self.random = random.Random(seed)

    def choose(
        self, candidates: list[ActionCandidate], executed: set[str] | None = None
    ) -> ActionCandidate | None:
        candidates = [item for item in candidates if item.key not in (executed or set())]
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]
        root = _Node()
        ordered = sorted(candidates, key=lambda item: (-item.prior, item.key))
        root.untried = list(ordered)
        for _ in range(self.simulations):
            self._simulate(root, candidates, set(executed or set()))
        if not root.children:
            return candidates[0]
        return max(
            root.children.values(),
            key=lambda node: (node.visits, node.value, node.action.prior if node.action else 0),
        ).action

    def _simulate(self, root: _Node, candidates: list[ActionCandidate], executed: set[str]) -> None:
        node = root
        state = set(executed)
        path: list[_Node] = [root]
        rewards: list[float] = []
        for _ in range(self.depth):
            available = [item for item in candidates if item.key not in state]
            if not available:
                break
            if node.untried:
                action = node.untried.pop(0)
                child = _Node(action, node)
                node.children[action.key] = child
            else:
                child = self._select(node)
                if child is None:
                    break
            state.add(child.action.key if child.action else "")
            path.append(child)
            reward = self._sample_reward(child.action, state) if child.action else 0.0
            rewards.append(reward)
            node = child

        # Light rollout below the expanded node. The target is not touched here;
        # this is only a model-based estimate.
        for _ in range(self.depth - len(rewards)):
            available = [item for item in candidates if item.key not in state]
            if not available:
                break
            action = self.random.choice(available)
            state.add(action.key)
            rewards.append(self._sample_reward(action, state))

        for index, item in enumerate(path):
            item.visits += 1
            item.value += sum(rewards[max(0, index - 1) :])

    def _select(self, node: _Node) -> _Node | None:
        if not node.children:
            return None
        best: _Node | None = None
        best_score = float("-inf")
        log_parent = math.log(max(1, node.visits))
        for child in node.children.values():
            if child.visits == 0:
                score = float("inf")
            else:
                exploit = child.value / child.visits
                explore = self.exploration * math.sqrt(log_parent / child.visits)
                score = exploit + explore
            if score > best_score:
                best = child
                best_score = score
        return best

    def _sample_reward(self, action: ActionCandidate, state: set[str]) -> float:
        if self.random.random() >= self.model.probability(action):
            return 0.0
        reward = self.model.reward(action)
        endpoint = action.endpoint.url if action.endpoint else ""
        if endpoint:
            for other in state:
                if other != action.key and endpoint in other:
                    reward += 0.12
                    break
        return reward


def severity_weight(severity: Severity) -> float:
    return severity.weight
