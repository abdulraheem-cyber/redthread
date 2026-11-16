# Architecture

redthread is a single-process Python application. A run loads one TOML config, opens one SQLite graph, authenticates a set of identities, crawls the in-scope target, executes checks, and writes a report. There is no server component and no database service to install.

## Run flow

```text
CLI
  |
  v
Config + Scope  ->  authorization guard
  |
  v
Authentication  ->  sessions keyed by identity
  |
  v
Discovery       ->  endpoints, forms, specs, GraphQL, hosts
  |
  v
Baseline phase  ->  round-robin actions across checks
  |
  v
Exploration     ->  MCTS over remaining actions, optional LLM suggestions
  |
  v
Replay          ->  verify candidates left in the graph
  |
  v
Report          ->  Markdown, JSON, SARIF, graph export
```

The orchestrator is in `src/redthread/orchestrator.py`. The CLI only parses arguments and prints a summary; it does not make HTTP requests.

## Phases

### 1. Configuration and scope

`config.py` reads TOML with `tomllib`, expands `${ENV_VAR}` references, validates types and section names, and builds immutable dataclasses. `scope.py` turns `scope.include` into match rules and rejects missing schemes, query strings, unsupported schemes, and malformed ports.

Before any run directory is created, `Scope.require_authorization()` checks whether every seed is loopback. A non-loopback seed without `run.authorized = true` aborts the run with exit code 2.

The run directory is named `<timestamp>-<run.name>` under `output_dir`. If that directory already exists, a numeric suffix is added. The directory is created before authentication so partial runs still have a place to write evidence.

### 2. Authentication

`agents/auth.py` supports five identity kinds:

- `form`: fetch the login page, parse the first form with a password field, submit it, and check a success marker or the absence of a login form.
- `basic`: set an Authorization header and optionally verify a protected URL.
- `bearer`: set a bearer token and optionally verify a protected URL.
- `headers`: set custom headers.
- `browser`: drive Chromium through Playwright, then copy cookies into the HTTP session.

Every identity gets its own `HttpSession`, so cookies and headers do not leak between identities. A failed login is recorded as a warning and the run continues with the other identities. The BOLA check is skipped when fewer than two identities authenticate.

### 3. Discovery

`agents/scan.py` does four things:

1. Tries a small list of OpenAPI and Swagger paths at each seed base.
2. Crawls HTML from the seed, following same-origin links up to `scope.max_depth` and `scope.max_pages`.
3. Records forms, query parameters, redirect sources, and API tags as endpoints.
4. Probes common GraphQL paths and stores introspection field names when a schema is returned.

When `scope.crawl_identities` is true, the crawler repeats the crawl with each authenticated session. This finds pages that anonymous users cannot reach. Discovery skips static assets, URLs outside scope, and paths matching the destructive-path pattern in `discovery.py`.

YAML OpenAPI requires the `yaml` extra. nmap support is optional and runs only when `integrations.nmap_enabled` is true.

### 4. Baseline

`checks.enabled_checks()` resolves the active check set. `planner.build_check_actions()` creates one action per applicable endpoint, check, and preferred identity. `baseline_order()` takes a round-robin slice across checks so that a check that matches many endpoints cannot consume the entire budget.

`ManagedAgent` runs the baseline actions concurrently with an asyncio semaphore. The default is four workers. Each worker calls `ActionRunner.run()`.

`ActionRunner` is responsible for the candidate lifecycle:

- Call `check.run()`.
- For each candidate, call `check.verify()` immediately.
- Save the finding as validated or rejected.
- Record the action, status, reward, and candidate count in the graph.
- Convert check exceptions into action errors instead of aborting the run.

### 5. Exploration

The exploration agent recalculates the remaining actions after the baseline. It adds any pending LLM suggestions and asks the MCTS planner to choose one action at a time. Each chosen action is executed, then the planner model is updated with success or failure.

The planner runs `simulations` model rollouts at depth 3. Rollouts never touch the target. They sample from a small probability model whose priors come from check severity and whose observations come from this run's action history. The random seed is fixed so a run is repeatable given the same graph and target responses.

Exploration stops when there are no untried actions, when `max_explore_actions` is reached, or when `stagnant_limit` actions produce neither findings nor new endpoints.

If an LLM is configured, it is asked for up to five suggestions every eight actions and when progress stalls. See the LLM section below.

### 6. Replay

The action runner verifies candidates immediately, so most findings never reach the end of the run as candidates. `Orchestrator._finish_candidates()` is a second pass for any candidate still in the graph. This handles interrupted verification and keeps the invariant that a candidate cannot appear as validated without a replay.

A rejected candidate is not deleted. The report has a separate rejected table, and `findings.json` includes `validation_note` and evidence so the decision can be reviewed.

### 7. Reporting

`reporting.py` reads all findings from the graph, sorts validated findings by severity and CVSS score, assigns display IDs (`RT-001`, and so on), and writes the artifacts. Display IDs are assigned per run.

Evidence redaction happens at report build time:

- URL query values with sensitive key names are replaced with `REDACTED`.
- Authorization, cookie, set-cookie, and API-key evidence fields are replaced.
- The audit log redacts URLs as they are written and never stores request bodies.

The Markdown report is generated from the same Python dictionary as `findings.json`, so the two cannot drift apart. SARIF is generated from the validated findings only.

## Knowledge graph

`graph.py` uses SQLite with WAL mode and a process-local re-entrant lock. The database is intentionally simple and portable.

Tables:

- `nodes(id, kind, key, props, created_at, updated_at)`, unique on `(kind, key)`.
- `edges(src, dst, kind, props, created_at)`, unique on `(src, dst, kind)`.
- `findings(id, check_id, severity, status, method, endpoint, parameter, discovered_by, data, ...)`.
- `actions(id, action_key, agent, status, reward, detail, created_at)`.
- `meta(key, value)`.

Node kinds currently used:

- `run`: one per run, with start time and scope.
- `host`: a host:port pair.
- `service`: an nmap service.
- `document`: an OpenAPI or GraphQL document.
- `endpoint`: method plus URL, with parameters, tags, and identities that saw it.
- `identity`: an authenticated or anonymous session.
- `tag`: a reusable endpoint tag.
- `hypothesis`: an LLM suggestion and its rationale.

Edge kinds:

- `SAW`: identity to endpoint.
- `TAGGED`: endpoint to tag.
- `DESCRIBED_BY`: endpoint to document.
- `MOTIVATES`: endpoint to hypothesis.
- `RUNS`: host to service.

`graph.json` exports nodes, edges, all findings, action counts, and an export timestamp. `redthread export-neo4j` loads that file into Neo4j as generic `RedthreadNode` nodes and `REDTHREAD_EDGE` relationships. This makes the graph portable but does not create a native label for every node kind; a Neo4j user should project labels from the `kind` property if needed.

The default graph path is inside the run directory, so runs are isolated. `graph.path` can point somewhere else, but the database is opened as-is and the report reads all findings present in it. Use a per-run path unless you are deliberately managing a shared graph.

## LLM integration

The LLM is optional and disabled by default. `llm.py` speaks the OpenAI chat-completions shape against any compatible base URL. It does not use tools, function calling, or streaming.

The prompt contains:

- scope include and exclude entries,
- up to 60 endpoints with method, path, redacted URL, parameter names, tags, identities, and a truncated note,
- the active check list with descriptions,
- up to 12 validated findings.

It does not contain cookies, tokens, passwords, request bodies, or response bodies. Endpoint notes and paths can still be sensitive; enabling the feature sends them to the configured provider.

Suggestions are parsed as JSON and treated as untrusted input. A suggestion is accepted only if:

- it names a registered, enabled check and an endpoint that exists in the graph, or
- it is a GET, HEAD, or OPTIONS request whose URL passes `Scope.check()` and the destructive-path filter.

The model cannot supply payloads to checks. A "focus" suggestion selects a check that will run its fixed probes. The model cannot declare a finding, change severity, or skip replay.

## Concurrency and limits

- HTTP sessions are asynchronous and isolated per identity.
- `RateLimiter` spaces requests globally across all sessions.
- `RunBudget` enforces request count, wall-clock time, and the stop file. The stop file is checked at most once per second.
- Baseline actions run concurrently up to `run.workers`.
- Exploration actions run sequentially so the planner can update after each result.
- SQLite access is serialised by a lock. Writes are small and flushed per action.
- HTTP response bodies are capped at 1.5 MB.

## Failure handling

- A check exception becomes an action error; other actions continue.
- An authentication failure becomes a warning; the run continues.
- A budget or stop-file hit ends the active phase, skips the rest of the run, and still writes a report with `stopped_reason`.
- A config or scope error aborts before traffic starts.
- An unexpected exception is logged, a partial report is attempted, and the exception is re-raised after cleanup.
- Every run closes HTTP clients, the graph, and the audit file in a `finally` block.

## Design choices

**Checks are code, not templates.** The check set is small enough to keep the signal and replay logic next to each other. A template language would make the replay contract harder to enforce.

**Validation is a request, not a reviewer.** "Validated" means the evidence was reproduced. This makes the label useful in automation, but it is not a claim of human confirmation.

**SQLite first, Neo4j optional.** The tool should run on a laptop or CI runner with no services. Neo4j is an export target for teams that already have a graph platform.

**The planner is bounded on purpose.** MCTS chooses among known actions. The optional LLM can widen the action set only within scope and method limits. Neither component is allowed to turn the scanner into an unbounded fuzzer.

**Rejected findings are data.** Keeping them makes false positives visible and gives reviewers a record of what the tool considered and why it changed its mind.
