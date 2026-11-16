from __future__ import annotations

import time
from pathlib import Path

from redthread.errors import BudgetExceeded, RunStopped


class RunBudget:
    """Request, time and kill-switch limits for one run."""

    def __init__(
        self,
        max_requests: int,
        max_runtime_seconds: float,
        stop_file: Path | None = None,
    ):
        self.max_requests = max_requests
        self.max_runtime = max_runtime_seconds
        self.stop_file = stop_file
        self.requests = 0
        self.started = time.monotonic()
        self.stopped_reason = ""
        self._last_stop_check = 0.0

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    @property
    def remaining_requests(self) -> int:
        return max(0, self.max_requests - self.requests)

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.max_runtime - self.elapsed)

    def stop(self, reason: str) -> None:
        self.stopped_reason = reason

    def _check_time(self) -> None:
        if self.elapsed >= self.max_runtime:
            self.stopped_reason = f"time limit reached ({self.max_runtime:.0f}s)"
            raise BudgetExceeded(self.stopped_reason)

    def _check_stop_file(self) -> None:
        if not self.stop_file:
            return
        now = time.monotonic()
        if now - self._last_stop_check < 1.0:
            return
        self._last_stop_check = now
        if self.stop_file.exists():
            reason = self.stop_file.read_text(encoding="utf-8", errors="replace").strip()
            self.stopped_reason = reason or f"stop file found: {self.stop_file}"
            raise RunStopped(self.stopped_reason)

    def consume_request(self) -> None:
        if self.stopped_reason:
            raise RunStopped(self.stopped_reason)
        self._check_time()
        self._check_stop_file()
        if self.requests >= self.max_requests:
            self.stopped_reason = f"request limit reached ({self.max_requests})"
            raise BudgetExceeded(self.stopped_reason)
        self.requests += 1

    def summary(self) -> dict[str, float | int | str]:
        return {
            "requests": self.requests,
            "max_requests": self.max_requests,
            "elapsed_seconds": round(self.elapsed, 2),
            "max_runtime_seconds": self.max_runtime,
            "stopped_reason": self.stopped_reason,
        }
