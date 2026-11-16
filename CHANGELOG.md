# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Initial Alpha Release

### Added
- Core exposure validation engine with non-destructive HTTP methods (GET, HEAD, OPTIONS, optional POST).
- Surface discovery for HTML hyperlinks and forms, OpenAPI 3.x specifications, and GraphQL introspection.
- Embedded SQLite knowledge graph tracking hosts, endpoints, identities, hypotheses, and findings.
- Bounded Monte Carlo Tree Search (MCTS) exploration planner with optional LLM action selector.
- Two-stage candidate replay validation gate to prevent false positives.
- Registered checks:
  - `authz-object` (Broken Object-Level Authorization / IDOR)
  - `sqli` (SQL syntax error injection)
  - `xss` (Reflected cross-site scripting)
  - `cors` (Permissive origin reflection with credentials)
  - `open-redirect` (Parameter destination validation)
  - `headers` (Missing security headers and software banners)
  - `graphql` (Introspection queries and field discovery)
- Multiple identity authenticators: Form, HTTP Basic, Bearer tokens, custom headers, and Playwright browser login.
- Report generation for Markdown (`report.md`), JSON (`findings.json`), SARIF (`findings.sarif`), and request audit logs (`audit.jsonl`).
- Neo4j graph export via Cypher statements (`redthread export-neo4j`).
- Benchmark evaluation harness with bundled deliberately vulnerable application (`labs/labshop.py`).
