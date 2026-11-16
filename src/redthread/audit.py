from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from redthread.scope import redact_url


class AuditLog:
    """Append-only JSONL record of requests and planning decisions.

    Bodies and credentials are deliberately not written here. Evidence for a
    finding lives in the graph and report, where it can be reviewed separately.
    """

    def __init__(self, path: Path, run_id: str):
        self.path = path
        self.run_id = run_id
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = path.open("a", encoding="utf-8")

    def record(self, event: str, **fields: Any) -> None:
        payload = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "run": self.run_id,
            "event": event,
        }
        payload.update(fields)
        line = json.dumps(payload, ensure_ascii=False, default=str)
        with self._lock:
            self._handle.write(line + "\n")
            self._handle.flush()

    def request(
        self,
        *,
        identity: str,
        method: str,
        url: str,
        status: int | None,
        bytes_read: int = 0,
        elapsed_ms: float = 0.0,
        error: str = "",
    ) -> None:
        data: dict[str, Any] = {
            "identity": identity,
            "method": method.upper(),
            "url": redact_url(url),
            "status": status,
            "bytes": bytes_read,
            "elapsed_ms": round(elapsed_ms, 1),
        }
        if error:
            data["error"] = error
        self.record("request", **data)

    def decision(self, actor: str, action: str, reason: str, **extra: Any) -> None:
        self.record("decision", actor=actor, action=action, reason=reason, **extra)

    def close(self) -> None:
        with self._lock:
            if not self._handle.closed:
                self._handle.close()
