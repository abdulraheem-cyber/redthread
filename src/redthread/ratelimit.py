from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """Global token spacing. One shared limiter per run, not per session."""

    def __init__(self, rate_per_second: float):
        self.rate = max(0.0, float(rate_per_second))
        self._interval = 1.0 / self.rate if self.rate else 0.0
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if not self.rate:
            return
        async with self._lock:
            now = time.monotonic()
            wait = self._next - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = time.monotonic()
            self._next = max(now, self._next) + self._interval
