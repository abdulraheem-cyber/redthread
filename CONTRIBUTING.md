# Contributing

## Development setup

```console
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # POSIX
pip install -e ".[dev]"
```

Optional dependencies:

```console
pip install -e ".[browser,yaml,neo4j]"
```

Run the checks before opening a pull request:

```console
python -m pytest
ruff check .
ruff format --check .
```

The test suite starts a local copy of the lab application on an ephemeral loopback port. It does not require a running server, network access, or external accounts.

## Code style

- Python 3.11 or newer.
- Line length 100.
- Ruff rules `E`, `F`, `I`, `UP`, and `B` are enabled.
- Use type hints on public functions and dataclasses.
- Keep comments for decisions and non-obvious behaviour, not for restating code.
- Avoid new runtime dependencies unless they are optional and justified.

## Adding a check

1. Add a subclass of `redthread.checks.base.Check` in `src/redthread/checks/`.
2. Implement `applies`, `run`, and `verify`.
3. Register it in `CHECK_CLASSES` in `src/redthread/checks/__init__.py`.
4. Add unit tests for the positive signal, the negative case, and replay.
5. If the lab can model the issue, add an end-to-end assertion and a truth-file entry.

The replay method must use evidence recorded by `run`. Do not return `ok=True` based only on a fresh heuristic; the point of replay is to confirm the specific evidence that produced the candidate.

Checks must be read-only. Do not add PUT, PATCH, DELETE, writes, uploads, password changes, or state-changing GraphQL mutations. POST is reserved for authentication and GraphQL introspection.

## Changing scope or request handling

Changes to `scope.py`, `http.py`, `budget.py`, or the authentication flow need tests for the refusal cases as well as the happy path. In particular:

- non-loopback seeds without authorization must fail,
- excluded paths must not receive traffic,
- unsupported methods must fail,
- redirects outside scope must fail,
- credentials must not appear in reports or the audit log.

## LLM changes

Model output is untrusted. Any new suggestion type must be validated against:

- the registered check set,
- the scope allowlist and exclude patterns,
- the destructive-path filter,
- the supported method set.

The model must not be able to supply a payload that a check sends, and it must not be able to set a finding status. Add tests that feed malicious or out-of-scope suggestions and assert that they are rejected.

## Reports and evidence

Report format changes should update the Markdown, JSON, and SARIF tests together. Artifacts are consumed by scripts, so avoid breaking field names without a deprecation path.

Do not include real credentials, customer data, or internal hostnames in fixtures, tests, screenshots, or benchmark files. Use reserved domains such as `example.test` and `redthread.invalid`.

## Commit and pull request scope

Keep changes focused. A new check should not also refactor the planner. If a change affects the default config, the example config, and the documentation, include all three in the same pull request.

Describe the behaviour change and the test evidence in the pull request. If you are changing a detection threshold, include the false-positive trade-off.
