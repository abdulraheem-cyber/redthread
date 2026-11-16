from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from redthread.agents.runner import ActionResult, ActionRunner
from redthread.errors import BudgetExceeded, RunStopped
from redthread.planner import ActionCandidate

log = logging.getLogger(__name__)


@dataclass
class PhaseResult:
    actions: int = 0
    validated: list[ActionResult] = field(default_factory=list)
    rejected: int = 0
    candidates: int = 0
    new_endpoints: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def findings(self):
        return [finding for result in self.validated for finding in result.findings]


class ManagedAgent:
    def __init__(self, runner: ActionRunner, workers: int = 4):
        self.runner = runner
        self.workers = max(1, workers)

    async def run(self, actions: list[ActionCandidate], phase: str = "baseline") -> PhaseResult:
        result = PhaseResult()
        if not actions:
            return result
        semaphore = asyncio.Semaphore(self.workers)
        done = 0

        async def one(action: ActionCandidate) -> ActionResult:
            async with semaphore:
                return await self.runner.run(action, phase)

        tasks = [asyncio.create_task(one(action)) for action in actions]
        try:
            for future in asyncio.as_completed(tasks):
                try:
                    item = await future
                except (BudgetExceeded, RunStopped):
                    for task in tasks:
                        task.cancel()
                    raise
                except Exception as exc:  # defensive: a worker bug is a run error
                    result.errors.append(f"{type(exc).__name__}: {exc}")
                    log.warning("action failed: %s", exc)
                    continue
                result.actions += 1
                done += 1
                result.candidates += item.candidates
                result.rejected += item.rejected_count
                result.new_endpoints += item.new_endpoints
                if item.findings:
                    result.validated.append(item)
                if item.error:
                    result.errors.append(item.error)
                if done % 10 == 0:
                    log.info("%s: %d/%d actions", phase, done, len(actions))
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
        return result
