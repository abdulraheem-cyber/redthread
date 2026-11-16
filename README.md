# redthread

redthread is a scope-aware exposure validation harness for web applications and APIs. It crawls a target, records what it finds in a small graph, runs deterministic checks, and replays every candidate finding before it appears in a report.

The project is an experiment in bounded automation: a planner can choose what to test next, and an optional language model can suggest actions, but neither one is allowed to invent new attack techniques or declare a finding. Checks produce candidates. A second request decides whether those candidates survive.

This is alpha software. It is intended for local labs, CI fixtures, and authorised assessment work.

## What it does

- Authenticates with form login, basic auth, bearer tokens, custom headers, or a Playwright-driven browser session.
- Discovers HTML links, forms, OpenAPI descriptions, GraphQL endpoints, and optionally nmap services.
- Builds a SQLite knowledge graph of hosts, endpoints, identities, documents, hypotheses, actions, and findings.
- Runs a baseline pass across registered checks, then a bounded MCTS-guided exploration pass.
- Optionally asks an OpenAI-compatible model to choose among already-discovered actions.
- Replays candidates and keeps rejected ones for audit instead of deleting them.
- Writes Markdown, JSON, SARIF, graph, and request-audit artifacts.
- Scores a run against a ground-truth file and exports the graph to Neo4j.

Supported request methods are GET, HEAD, OPTIONS, and, only when explicitly enabled, POST. There is no PUT, PATCH, DELETE, or file upload. The optional nmap integration starts the configured nmap binary without a shell; the optional browser login starts a headless Chromium through Playwright.

## Requirements

- Python 3.11 or newer
- `httpx` (installed with the package)
- Optional: Playwright for JavaScript login flows
- Optional: PyYAML for YAML OpenAPI documents
- Optional: the `neo4j` driver for graph export

## Install

```console
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # POSIX
pip install -e ".[dev]"
```

Optional extras:

```console
pip install -e ".[browser,yaml,neo4j]"
```

## Quick start against the lab

The repository includes `labs/labshop.py`, a deliberately vulnerable application with form authentication, SQL injection, reflected XSS, an open redirect, permissive CORS, missing headers, broken object-level authorisation, and a GraphQL endpoint.

Start it in one terminal:

```console
python -m labs.labshop --port 8000
```

Run the scanner in another terminal:

```console
redthread validate -c examples/redthread.toml
redthread run -c examples/redthread.toml
```

The run prints a summary similar to this:

```text
run directory: C:\...\runs\2026-11-06_212117-labshop
validated: 8 (low 2, medium 3, high 3), rejected: 0, requests: 86
  RT-001 high     authz-object [101] GET http://127.0.0.1:8000/api/orders/101
  RT-002 high     authz-object [102] GET http://127.0.0.1:8000/api/orders/102
  RT-003 high     sql-injection [q] GET http://127.0.0.1:8000/search?q=books
  ...
report: C:\...\runs\2026-11-06_212117-labshop\report.md
```

Score the run against the bundled ground truth:

```console
redthread eval --run runs/2026-11-06_212117-labshop --truth benchmarks/truth-labshop.json --strict
```

For a fresh config outside the example:

```console
redthread init redthread.toml
redthread validate -c redthread.toml
```

`validate` does not send traffic. It parses the file and prints the effective scope, methods, identities, and enabled checks.

## Commands

| Command | Purpose |
| --- | --- |
| `redthread run -c CONFIG` | Execute one run. `--fail-on` returns non-zero when a validated finding reaches a severity threshold. `--json` prints a machine-readable summary. |
| `redthread watch -c CONFIG` | Repeat runs on an interval. `--max-runs 0` means until interrupted. |
| `redthread validate -c CONFIG` | Parse the config and print the effective scope without making requests. |
| `redthread init PATH` | Write a starter TOML file. `--force` overwrites an existing file. |
| `redthread checks` | List registered checks, their default severities, and titles. |
| `redthread eval --run DIR --truth FILE` | Score `findings.json` against a ground-truth file. `--strict` fails on missing or unexpected findings. |
| `redthread export-neo4j --run DIR --uri URI` | Load a run's `graph.json` into Neo4j. Credentials can come from the config or CLI flags. |

`run` also accepts `--no-llm`, `--no-explore`, and `--quiet`. `watch` accepts the same planner options.

## Configuration

Configuration is TOML. Paths in `output_dir`, `graph.path`, and `stop_file` are relative to the config file. String values support `${ENV_VAR}` expansion.

```toml
[run]
name = "staging"
output_dir = "runs"
authorized = false
allow_post = false
rate_limit = 4.0
max_requests = 800
max_runtime_seconds = 900
workers = 4

[scope]
include = ["https://staging.example.test"]
exclude = ["/logout", "/admin/delete*"]
max_depth = 3
max_pages = 80
same_origin = true

[checks]
enabled = []        # empty means every registered check
disabled = ["headers"]

[integrations]
nmap_enabled = false

[[identities]]
name = "analyst"
kind = "form"
login_url = "https://staging.example.test/login"
username = "${TEST_USER}"
password = "${TEST_PASSWORD}"
success_marker = "Signed out"
```

`run.authorized` must be `true` for any seed that is not loopback. `run.allow_post` enables POST for form authentication and GraphQL introspection. If POST is listed in `run.allowed_methods` but `allow_post` is false, config loading fails.

Identity kinds are `form`, `basic`, `bearer`, `headers`, and `browser`. The browser kind requires the `browser` extra. The annotated example config is in `examples/redthread.toml`.

## Checks

| ID | Default severity | Signal |
| --- | --- | --- |
| `headers` | low | Missing CSP, `X-Content-Type-Options`, anti-framing policy, Referrer-Policy, HSTS on HTTPS, or software banner disclosure. Runs once per origin. |
| `cors` | medium | An API or GraphQL endpoint reflects an arbitrary Origin and allows credentials. |
| `open-redirect` | medium | A known redirect parameter returns a 3xx to an external URL. |
| `graphql-introspection` | low | A GraphQL endpoint answers an introspection query. Enabled when POST is allowed. |
| `reflected-xss` | medium | A query parameter is reflected into HTML without the HTML-sensitive characters being encoded. |
| `sql-injection` | high | A quote produces database error text, or a true/false pair creates a stable response difference. No write statements are sent. |
| `authz-object` | high | Two authenticated identities can read the same object, and an anonymous client cannot. Requires at least two identities. |

A finding is only produced after the check observes its signal. Validation is a separate request that repeats the specific evidence. Validation is not human review, and the report says so.

See `docs/checks.md` for payloads, thresholds, and false-positive controls.

## Finding lifecycle

1. A check runs against an endpoint and returns zero or more candidates.
2. The runner immediately calls the check's `verify` method.
3. If the evidence reproduces, the candidate becomes `validated`. If not, it becomes `rejected` with a note explaining what changed.
4. Candidates still unverified when a budget or stop file ends the run remain `unverified` in the report.
5. Rejected and unverified candidates stay in the graph and JSON report.

Confidence is check-specific and reflects how strong the replay was. It is not a probability calibrated against real-world exploitability. CVSS scores are computed from the base vector attached to each check; they do not include environmental adjustments.

## Output

Each run gets its own directory:

| File | Contents |
| --- | --- |
| `findings.json` | Full report: summary, scope, identities, coverage, validated findings, rejected candidates, unverified candidates, errors. |
| `run.json` | Run metadata, summary, scope, and errors. |
| `report.md` | Human-readable report with evidence and remediation. |
| `findings.sarif` | SARIF 2.1.0 results for code scanning or CI ingestion. |
| `graph.json` | Portable export of graph nodes, edges, findings, and action counts. |
| `graph.sqlite` | Live SQLite graph used during the run. WAL files may be present while it is open. |
| `audit.jsonl` | Append-only request and decision log. URLs are redacted and bodies are not stored. |
| `redthread.log` | Runtime log. |

Credentials are not written to reports or the audit file. Sensitive query parameters and authentication headers are redacted from evidence. Response excerpts are not otherwise scrubbed, so a run directory can contain application data. Treat it as sensitive test output.

## Safety model

The scanner is deny-by-default:

- Every request passes through the scope allowlist and exclude patterns.
- Non-loopback seeds are refused unless `run.authorized = true`. The flag is the operator's assertion of permission; the tool cannot verify it.
- Only GET, HEAD, OPTIONS, and opt-in POST are permitted.
- POST is used for authentication and GraphQL introspection. Checks do not send mutations, writes, deletes, uploads, or password changes.
- Discovery skips URLs that look destructive (`logout`, `delete`, `remove`, `destroy`, `reset`, `revoke`, `unsubscribe`), even when they are inside scope.
- Request count, runtime, rate, baseline actions, exploration actions, and stagnation are bounded.
- A stop file is checked before the run and during requests. Creating it stops the run and produces a partial report.
- The optional LLM never receives credentials or response bodies. It gets redacted URLs, parameter names, endpoint notes, and finding summaries. Its output is treated as untrusted and is restricted to registered checks or GET/HEAD/OPTIONS discovery probes.

These controls reduce accidental damage. They do not make the tool safe to point at arbitrary systems, and they do not replace written authorisation or a rules-of-engagement review.

The lab is intentionally vulnerable. Keep it bound to `127.0.0.1`.

More detail is in `docs/safety.md`.

## Benchmark

`benchmarks/truth-labshop.json` describes the seven seeded issue classes in the lab. The current end-to-end result is:

| Metric | Value |
| --- | ---: |
| Expected issue classes | 7 |
| Findings | 8 |
| Matched issue classes | 7 |
| True positives | 8 |
| False positives | 0 |
| Precision | 1.000 |
| Recall | 1.000 |
| F1 | 1.000 |

There are eight findings because the lab has two order objects and the BOLA check reports each cross-account read as a separate finding; the truth file treats object-level authorisation as one expected class. This is a small synthetic benchmark, not evidence of general detection quality. `docs/benchmarks.md` explains the scoring and its limits.

## Limitations

- The check set is small and deliberately conservative. It is not a replacement for a full DAST scanner or manual testing.
- XSS detection is based on raw reflection in HTML, not browser execution. A reflected payload may still be blocked by a CSP or browser parser in practice.
- SQL injection uses error signatures and boolean differentials only. It does not attempt time-based, out-of-band, or stacked queries.
- Object-level authorisation checks use body similarity and object identifiers in paths or common query parameters. They can miss binary responses, paginated objects, and endpoints that do not expose an identifier.
- GraphQL support is discovery plus introspection. It does not test resolver authorisation or query cost limits.
- JavaScript-heavy applications need the browser login option, and crawling still relies on server-rendered HTML and links. There is no full browser crawler.
- The planner is a small in-process MCTS model. It does not train or persist a policy across runs.
- Multi-step business logic, race conditions, OAuth flows, MFA bypass, and file upload issues are out of scope.
- Reports contain response excerpts. Review them before sharing outside the assessment team.
- The project is designed against the Tier 1 control ideas in OWASP APTS. It is not certified against APTS or any other standard, and it does not implement a compliance programme.

## Prior art

redthread borrows heavily from existing tools and ideas: OWASP ZAP for baseline scanning and replay, Burp Suite for authenticated crawling and manual validation, Nuclei for template-driven checks, Nikto for simple web server checks, and graph-based attack-path tools for modelling relationships between assets and identities. The MCTS planner is a small application of a well-known search technique. The contribution here is the combination: a bounded planner, deterministic checks, replay validation, a persistent graph, and an audit trail in one readable Python codebase. It does not claim novel vulnerability research.

`docs/prior-art.md` has a longer comparison.

## Project layout

```text
src/redthread/
  agents/          authentication, crawling, action execution, exploration
  checks/          deterministic checks and replay validators
  integrations/    OpenAPI, GraphQL, nmap
  benchmark.py     ground-truth scoring
  cli.py           command-line entry point
  config.py        TOML parsing and validation
  graph.py         SQLite knowledge graph
  http.py          scoped HTTP session
  orchestrator.py  run phases and artifact generation
  planner.py       baseline ordering and MCTS
  reporting.py     Markdown, JSON, and SARIF output
  scope.py         allowlist, excludes, redaction
labs/              deliberately vulnerable demo application
benchmarks/        ground-truth files
examples/          sample config
tests/             unit, integration, and end-to-end tests
docs/              design, safety, checks, benchmarks, prior art
```

## Development

```console
python -m pytest
ruff check .
ruff format --check .
```

The end-to-end test starts the lab on an ephemeral loopback port. It does not require a separate server process, and it does not write outside pytest's temporary directories.

Ruff uses a 100-character line length and targets Python 3.11. Tests use pytest with asyncio mode enabled.

## License

MIT. See `LICENSE`.
