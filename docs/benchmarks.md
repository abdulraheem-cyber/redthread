# Benchmarks

The benchmark support compares a completed run with a JSON file that lists the issues the target is known to contain. It is a regression check for the checks and the crawler, not a general measure of scanner quality.

## Lab target

`labs/labshop.py` is a loopback-only application with:

- form login for `alice` and `bob`,
- two orders, one owned by each user, served without an ownership check,
- a product page that reflects the `category` query parameter into HTML,
- a search page that concatenates `q` into SQLite SQL,
- a redirect endpoint that accepts an absolute external URL in `next`,
- an API endpoint that reflects Origin and allows credentials,
- a GraphQL endpoint that answers introspection,
- responses without the baseline security headers.

The two accounts exist so the object-authorisation check has a victim and an attacker. The lab also has an anonymous control: both order endpoints return 401 without a session, which keeps the BOLA evidence meaningful.

## Ground-truth format

`benchmarks/truth-labshop.json`:

```json
{
  "name": "labshop-v1",
  "target": "http://127.0.0.1:8000",
  "findings": [
    {
      "check_id": "sql-injection",
      "path_contains": "/search",
      "parameter": "q"
    },
    {
      "check_id": "authz-object",
      "path_contains": "/api/orders/",
      "min_count": 1
    }
  ]
}
```

An expectation can use:

- `check_id` (required): must match a finding's check ID.
- `parameter`: exact parameter name. Omit to accept any parameter.
- `path`: exact URL path. Query strings are ignored.
- `path_contains`: substring of the URL path.
- `min_count`: number of findings required to satisfy the expectation. Defaults to 1.
- `note`: free text for humans.

`findings` may also be named `expected`. The loader accepts either.

A validated finding is matched against expectations in file order. The first matching expectation gets the credit. Findings that match no expectation are counted as unexpected. Rejected and unverified candidates are not included in the score.

## Metrics

- `expected`: number of expectations.
- `satisfied`: number of expectations whose observed count reaches `min_count`.
- `true_positives`: number of validated findings matched to an expectation, counted per finding.
- `false_positives`: number of validated findings that match no expectation.
- `false_negatives`: number of unsatisfied expectations.
- `precision`: true positives divided by true positives plus false positives.
- `recall`: satisfied expectations divided by expected expectations.
- `f1`: harmonic mean of precision and recall.

Precision is counted per finding while recall is counted per expectation. This asymmetry matters for BOLA. The truth file treats object-level authorisation as one expected class with `min_count: 1`, while a run that finds both cross-account directions produces two findings. The second finding is a true positive, not a false positive, and recall does not increase beyond one.

`redthread eval` prints missing and unexpected items. `--strict` exits 1 when either list is non-empty, which is suitable for CI.

## Current result

The recorded run is `runs/2026-11-06_212117-labshop`. It used `examples/redthread.toml`, the offline planner, and the lab on port 8000.

```console
redthread eval --run runs/2026-11-06_212117-labshop --truth benchmarks/truth-labshop.json --strict
```

```text
benchmark: labshop-v1
run: 2026-11-06_212117-labshop
expected 7, matched 7, precision 1.000, recall 1.000, f1 1.000
```

| Metric | Value |
| --- | ---: |
| Expected issue classes | 7 |
| Findings | 8 |
| Matched issue classes | 7 |
| True positives | 8 |
| False positives | 0 |
| False negatives | 0 |
| Precision | 1.000 |
| Recall | 1.000 |
| F1 | 1.000 |

Coverage by expectation:

| Check | Expected | Satisfied |
| --- | ---: | ---: |
| `authz-object` | 1 | 1 |
| `cors` | 1 | 1 |
| `graphql-introspection` | 1 | 1 |
| `headers` | 1 | 1 |
| `open-redirect` | 1 | 1 |
| `reflected-xss` | 1 | 1 |
| `sql-injection` | 1 | 1 |

The run recorded 86 requests, 15 actions, and 13.97 seconds. The two BOLA findings are `RT-001` for order 101 and `RT-002` for order 102.

## Reproduction

Start the lab:

```console
python -m labs.labshop --port 8000
```

Run the example config:

```console
redthread run -c examples/redthread.toml
```

Score the printed run directory:

```console
redthread eval --run runs/<timestamp>-labshop --truth benchmarks/truth-labshop.json --strict
```

The automated end-to-end test does the same work on an ephemeral port and asserts that all seven checks produce validated findings. It does not depend on the recorded run or on port 8000.

## Limits

- The sample size is one synthetic application. A perfect score says the checks recognise the issues they were written to find. It says nothing about detection on a different stack.
- The ground truth describes issue classes, not every endpoint where an issue could appear. The header expectation is endpoint-agnostic.
- The benchmark scores only findings that survived replay. A conservative check that rejects a real issue lowers recall; an aggressive check that validates a false lead lowers precision.
- The lab is built to match the checks. It is useful as a regression suite, but it is not an independent evaluation set.
- Crawl order can vary with page structure and server responses. The MCTS planner is seeded, but the discovery graph is not guaranteed to be byte-for-byte identical across applications.
- The benchmark does not measure request efficiency, time to first finding, or operator effort.

## Adding a benchmark

1. Add the deliberately vulnerable case to a lab or a disposable target.
2. Record the expected check ID, parameter, and path. Use `path_contains` when the exact path varies.
3. Set `min_count` when one issue class can produce several valid findings.
4. Run the scanner and score with `--strict`.
5. Keep the truth file under version control and document any case that is intentionally not covered.

Do not add an expectation for an issue the check cannot observe. A benchmark that scores the tool against its own assumptions is still useful for regressions, but it should not be presented as independent evidence.
