from __future__ import annotations

import json
from pathlib import Path

from redthread.errors import RedthreadError


def export_graph(
    path: str | Path,
    *,
    uri: str,
    user: str = "",
    password: str = "",
    database: str = "neo4j",
    batch_size: int = 500,
) -> dict[str, int]:
    try:
        from neo4j import GraphDatabase
    except ImportError as exc:
        raise RedthreadError(
            "the neo4j driver is not installed; pip install 'redthread[neo4j]'"
        ) from exc

    source = Path(path)
    if not source.exists():
        raise RedthreadError(f"graph export not found: {source}")
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RedthreadError(f"could not read {source}: {exc}") from exc

    nodes = [item for item in data.get("nodes", []) if isinstance(item, dict)]
    edges = [item for item in data.get("edges", []) if isinstance(item, dict)]
    findings = [item for item in data.get("findings", []) if isinstance(item, dict)]
    batch = max(1, batch_size)

    driver = GraphDatabase.driver(uri, auth=(user, password))
    try:
        with driver.session(database=database) as session:
            session.run(
                "CREATE CONSTRAINT redthread_node_rid IF NOT EXISTS "
                "FOR (n:RedthreadNode) REQUIRE n.rid IS UNIQUE"
            )
            for start in range(0, len(nodes), batch):
                rows = [
                    {
                        "rid": str(item.get("id")),
                        "kind": str(item.get("kind", "")),
                        "key": str(item.get("key", "")),
                        "props": json.dumps(item.get("props", {}), ensure_ascii=False),
                    }
                    for item in nodes[start : start + batch]
                ]
                session.run(
                    "UNWIND $rows AS row "
                    "MERGE (n:RedthreadNode {rid: row.rid}) "
                    "SET n.kind = row.kind, n.key = row.key, n.props = row.props",
                    rows=rows,
                )
            for start in range(0, len(findings), batch):
                rows = [
                    {
                        "rid": f"finding:{item.get('id', '')}",
                        "key": str(item.get("id", "")),
                        "props": json.dumps(item, ensure_ascii=False),
                    }
                    for item in findings[start : start + batch]
                ]
                session.run(
                    "UNWIND $rows AS row "
                    "MERGE (n:RedthreadNode {rid: row.rid}) "
                    "SET n.kind = 'finding', n.key = row.key, n.props = row.props",
                    rows=rows,
                )
            for start in range(0, len(edges), batch):
                rows = [
                    {
                        "src": str(item.get("src")),
                        "dst": str(item.get("dst")),
                        "kind": str(item.get("kind", "")),
                        "props": json.dumps(item.get("props", {}), ensure_ascii=False),
                    }
                    for item in edges[start : start + batch]
                ]
                session.run(
                    "UNWIND $rows AS row "
                    "MATCH (a:RedthreadNode {rid: row.src}) "
                    "MATCH (b:RedthreadNode {rid: row.dst}) "
                    "MERGE (a)-[r:REDTHREAD_EDGE {kind: row.kind}]->(b) "
                    "SET r.props = row.props",
                    rows=rows,
                )
    except Exception as exc:
        raise RedthreadError(f"Neo4j export failed: {exc}") from exc
    finally:
        driver.close()

    return {"nodes": len(nodes), "edges": len(edges), "findings": len(findings)}


def graph_path_for_run(run_dir: str | Path) -> Path:
    return Path(run_dir) / "graph.json"
