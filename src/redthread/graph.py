from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from redthread.models import Endpoint, Finding, Status, utcnow


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _loads(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        data = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


class Graph:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._create_schema()

    def _create_schema(self) -> None:
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS nodes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL,
                    key TEXT NOT NULL,
                    props TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(kind, key)
                );

                CREATE TABLE IF NOT EXISTS edges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
                    dst INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    props TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    UNIQUE(src, dst, kind)
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    check_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    method TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    parameter TEXT,
                    discovered_by TEXT NOT NULL,
                    data TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action_key TEXT NOT NULL,
                    agent TEXT NOT NULL,
                    status TEXT NOT NULL,
                    reward REAL NOT NULL DEFAULT 0,
                    detail TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_nodes_kind ON nodes(kind);
                CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src);
                CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
                CREATE INDEX IF NOT EXISTS idx_actions_key ON actions(action_key);
                """
            )
        self.set_meta("schema_version", "1")

    def set_meta(self, key: str, value: Any) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, _dumps(value) if not isinstance(value, str) else value),
            )

    def get_meta(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def upsert_node(self, node_kind: str, node_key: str, **props: Any) -> int:
        now = utcnow()
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT id, props FROM nodes WHERE kind=? AND key=?", (node_kind, node_key)
            ).fetchone()
            if row:
                current = _loads(row["props"])
                current.update(props)
                self._conn.execute(
                    "UPDATE nodes SET props=?, updated_at=? WHERE id=?",
                    (_dumps(current), now, row["id"]),
                )
                return int(row["id"])
            cursor = self._conn.execute(
                "INSERT INTO nodes(kind, key, props, created_at, updated_at) VALUES(?,?,?,?,?)",
                (node_kind, node_key, _dumps(props), now, now),
            )
            return int(cursor.lastrowid)

    def node_id(self, kind: str, key: str) -> int | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM nodes WHERE kind=? AND key=?", (kind, key)
            ).fetchone()
        return int(row["id"]) if row else None

    def get_node(self, kind: str, key: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM nodes WHERE kind=? AND key=?", (kind, key)
            ).fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "kind": row["kind"],
            "key": row["key"],
            "props": _loads(row["props"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def add_edge(self, src: int, dst: int, kind: str, **props: Any) -> int:
        now = utcnow()
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO edges(src, dst, kind, props, created_at) VALUES(?,?,?,?,?) "
                "ON CONFLICT(src, dst, kind) DO UPDATE SET props=excluded.props",
                (src, dst, kind, _dumps(props), now),
            )
        return 0

    def link(self, src: tuple[str, str], dst: tuple[str, str], kind: str, **props: Any) -> None:
        src_id = self.upsert_node(*src)
        dst_id = self.upsert_node(*dst)
        self.add_edge(src_id, dst_id, kind, **props)

    def neighbors(self, node_id: int, kind: str | None = None) -> list[dict[str, Any]]:
        query = (
            "SELECT n.*, e.kind AS edge_kind, e.props AS edge_props "
            "FROM edges e JOIN nodes n ON n.id=e.dst WHERE e.src=?"
        )
        params: list[Any] = [node_id]
        if kind:
            query += " AND e.kind=?"
            params.append(kind)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [
            {
                "id": row["id"],
                "kind": row["kind"],
                "key": row["key"],
                "props": _loads(row["props"]),
                "edge": _loads(row["edge_props"]),
            }
            for row in rows
        ]

    def upsert_endpoint(self, endpoint: Endpoint) -> int:
        existing = self.get_node("endpoint", endpoint.key)
        if existing:
            old = Endpoint.from_dict(existing["props"])
            merged = Endpoint(
                method=old.method,
                url=old.url,
                params={**old.params, **endpoint.params},
                source=endpoint.source or old.source,
                identities=tuple(sorted(set(old.identities) | set(endpoint.identities))),
                tags=tuple(sorted(set(old.tags) | set(endpoint.tags))),
                note=endpoint.note or old.note,
            )
            node = self.upsert_node("endpoint", merged.key, **merged.to_dict())
        else:
            merged = endpoint
            node = self.upsert_node("endpoint", endpoint.key, **endpoint.to_dict())

        for identity in merged.identities:
            identity_id = self.upsert_node("identity", identity, name=identity)
            self.add_edge(identity_id, node, "SAW", source=merged.source)
        for tag in merged.tags:
            self.add_edge(node, self.upsert_node("tag", tag, name=tag), "TAGGED")
        return node

    def endpoints(self) -> list[Endpoint]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT props FROM nodes WHERE kind='endpoint' ORDER BY id"
            ).fetchall()
        endpoints = []
        for row in rows:
            try:
                endpoints.append(Endpoint.from_dict(_loads(row["props"])))
            except (KeyError, TypeError):
                continue
        return endpoints

    def endpoint_for_url(self, url: str, method: str = "GET") -> Endpoint | None:
        key = f"{method.upper()} {url}"
        node = self.get_node("endpoint", key)
        if not node:
            return None
        try:
            return Endpoint.from_dict(node["props"])
        except (KeyError, TypeError):
            return None

    def record_action(
        self,
        action_key: str,
        agent: str,
        status: str,
        reward: float = 0.0,
        detail: dict[str, Any] | None = None,
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO actions(action_key, agent, status, reward, detail, created_at) "
                "VALUES(?,?,?,?,?,?)",
                (action_key, agent, status, float(reward), _dumps(detail or {}), utcnow()),
            )

    def actions_run(self) -> set[str]:
        with self._lock:
            rows = self._conn.execute("SELECT DISTINCT action_key FROM actions").fetchall()
        return {row["action_key"] for row in rows}

    def action_stats(self) -> dict[str, dict[str, float]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT action_key, COUNT(*) AS runs, "
                "SUM(CASE WHEN status='validated' THEN 1 ELSE 0 END) AS wins, "
                "AVG(reward) AS reward "
                "FROM actions GROUP BY action_key"
            ).fetchall()
        return {
            row["action_key"]: {
                "runs": int(row["runs"]),
                "wins": int(row["wins"]),
                "reward": float(row["reward"] or 0.0),
            }
            for row in rows
        }

    def action_counts(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT status, COUNT(*) AS n FROM actions GROUP BY status"
            ).fetchall()
        return {row["status"]: int(row["n"]) for row in rows}

    def save_finding(self, finding: Finding) -> None:
        now = utcnow()
        payload = _dumps(finding.to_dict())
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT data FROM findings WHERE id=?", (finding.id,)
            ).fetchone()
            if not row:
                self._conn.execute(
                    "INSERT INTO findings(id, check_id, severity, status, method, endpoint, "
                    "parameter, discovered_by, data, created_at, updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        finding.id,
                        finding.check_id,
                        finding.severity.value,
                        finding.status.value,
                        finding.method,
                        finding.endpoint,
                        finding.parameter,
                        finding.discovered_by,
                        payload,
                        finding.created_at,
                        now,
                    ),
                )
                return

            current = Finding.from_dict(_loads(row["data"]))
            rank = {
                Status.SKIPPED: 0,
                Status.CANDIDATE: 1,
                Status.REJECTED: 2,
                Status.VALIDATED: 3,
            }
            keep_current = rank.get(current.status, 0) > rank.get(finding.status, 0)
            chosen = current if keep_current else finding
            if chosen is finding and finding.status == Status.VALIDATED:
                finding.verified_at = finding.verified_at or now
            self._conn.execute(
                "UPDATE findings SET severity=?, status=?, data=?, updated_at=? WHERE id=?",
                (
                    chosen.severity.value,
                    chosen.status.value,
                    _dumps(chosen.to_dict()),
                    now,
                    finding.id,
                ),
            )

    def update_finding(
        self,
        finding_id: str,
        status: Status,
        *,
        confidence: float | None = None,
        evidence: dict[str, Any] | None = None,
        note: str = "",
    ) -> Finding | None:
        current = self.get_finding(finding_id)
        if not current:
            return None
        current.status = status
        current.verified_at = utcnow()
        if confidence is not None:
            current.confidence = confidence
        if evidence is not None:
            current.evidence = evidence
        if note:
            current.evidence = {**current.evidence, "validation_note": note}
        self.save_finding(current)
        return current

    def get_finding(self, finding_id: str) -> Finding | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM findings WHERE id=?", (finding_id,)
            ).fetchone()
        if not row:
            return None
        return Finding.from_dict(_loads(row["data"]))

    def findings(self, status: Status | str | None = None) -> list[Finding]:
        query = "SELECT data FROM findings"
        params: list[Any] = []
        if status is not None:
            query += " WHERE status=?"
            params.append(status.value if isinstance(status, Status) else status)
        query += " ORDER BY created_at, id"
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [Finding.from_dict(_loads(row["data"])) for row in rows]

    def finding_counts(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT status, COUNT(*) AS n FROM findings GROUP BY status"
            ).fetchall()
        return {row["status"]: int(row["n"]) for row in rows}

    def count_nodes(self, kind: str | None = None) -> int:
        with self._lock:
            if kind:
                row = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM nodes WHERE kind=?", (kind,)
                ).fetchone()
            else:
                row = self._conn.execute("SELECT COUNT(*) AS n FROM nodes").fetchone()
        return int(row["n"]) if row else 0

    def stats(self) -> dict[str, Any]:
        counts = self.finding_counts()
        with self._lock:
            by_severity = self._conn.execute(
                "SELECT severity, COUNT(*) AS n FROM findings "
                "WHERE status='validated' GROUP BY severity"
            ).fetchall()
        return {
            "nodes": self.count_nodes(),
            "endpoints": self.count_nodes("endpoint"),
            "identities": self.count_nodes("identity"),
            "findings": counts,
            "validated_by_severity": {row["severity"]: int(row["n"]) for row in by_severity},
            "actions": self.action_counts(),
        }

    def export_json(self, path: str | Path) -> Path:
        target = Path(path)
        nodes = []
        with self._lock:
            for row in self._conn.execute("SELECT * FROM nodes ORDER BY id"):
                nodes.append(
                    {
                        "id": row["id"],
                        "kind": row["kind"],
                        "key": row["key"],
                        "props": _loads(row["props"]),
                    }
                )
            edges = [
                {
                    "src": row["src"],
                    "dst": row["dst"],
                    "kind": row["kind"],
                    "props": _loads(row["props"]),
                }
                for row in self._conn.execute("SELECT * FROM edges ORDER BY id")
            ]
        payload = {
            "nodes": nodes,
            "edges": edges,
            "findings": [item.to_dict() for item in self.findings()],
            "actions": self.action_counts(),
            "exported_at": datetime.now(UTC).isoformat(timespec="seconds"),
        }
        target.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return target

    def iter_findings(self, status: Status | None = None) -> Iterable[Finding]:
        return iter(self.findings(status))

    def close(self) -> None:
        with self._lock:
            self._conn.close()
