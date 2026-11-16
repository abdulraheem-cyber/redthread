# Checks

Every check follows the same contract:

1. `run` inspects an endpoint and returns candidate findings only when its signal is present.
2. `verify` repeats the specific request and confirms that the evidence still holds.
3. The action runner records the action and stores the finding as `validated`, `rejected`, or `unverified`.

Checks never decide their own status. They return a `ValidationResult`, and the runner applies it. If a check raises an exception, the action is marked as an error and the run continues.

All checks are read-only with respect to application state. The only POST requests are form login and GraphQL introspection.

## `headers`

Default severity: low.

The check runs once per origin. It sends GET to the endpoint selected for that origin and looks at four response headers:

- `Content-Security-Policy`
- `X-Content-Type-Options`
- `X-Frame-Options` (satisfied by a CSP `frame-ancestors` directive)
- `Referrer-Policy`

On HTTPS it also looks for `Strict-Transport-Security`. If the response is `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true`, that is added to the missing list. `Server` and `X-Powered-By` values are stored as banner disclosure.

The check returns a finding when anything is missing or a banner is present. It skips responses with status 500 or above.

Replay requests the same endpoint and reports which baseline headers are still absent. The replay does not re-check HSTS, CORS, or banners. As a result, a finding caused only by banner disclosure is normally rejected on replay. The bundled lab has missing headers, so it validates.

Action key: `headers|<origin>`. The check intentionally runs once per origin regardless of the number of identities, because these headers are usually origin-wide. Per-path differences are not covered.

False-positive notes: a missing header is a hardening gap, not a vulnerability by itself. The report uses low severity and says so in the description.

## `cors`

Default severity: medium.

Applies to GET endpoints tagged `api` or `graphql`, paths containing `/api/`, and paths ending in `/graphql`.

The probe sends `Origin: https://redthread.invalid`. A finding requires the response to reflect that exact origin in `Access-Control-Allow-Origin` and to set `Access-Control-Allow-Credentials: true`. Wildcard origins are not enough for this check; the wildcard-with-credentials combination is handled by the header check.

Replay repeats the request with the same origin. Confidence is 0.9.

False-positive notes: `redthread.invalid` is a reserved domain, so a reflection cannot point at a real third-party site. The check does not test `null` origins, suffix matching, or preflight behaviour.

## `open-redirect`

Default severity: medium.

Applies to GET requests with a query parameter named `next`, `url`, `redirect`, `redirect_uri`, `return`, `return_to`, `continue`, `target`, `dest`, `destination`, or `callback`.

The payload is `https://redthread.invalid/rt-<random>`. The request does not follow redirects. A candidate requires a 3xx status and a `Location` header whose host is `redthread.invalid` or whose value contains the random marker.

Replay sends the same parameter and payload. The validator requires a 3xx response with `redthread.invalid` in `Location`. Confidence is 0.95.

False-positive notes: only absolute external URLs to a reserved domain are used. The check does not claim that every redirect parameter is exploitable in a real browser flow, and it does not attempt bypasses against allowlists.

## `graphql-introspection`

Default severity: low.

Applies to GET endpoints tagged `graphql` or with a path ending in `/graphql`. The check is enabled only when `run.allow_post = true`, because it sends the introspection query as a JSON POST.

The query asks for `queryType`, `mutationType`, and the type list. A candidate requires a response below status 400, a JSON body, a `data.__schema` object, and at least one type.

Replay sends the same query again. Confidence is 0.95.

False-positive notes: public introspection is an information exposure issue, not an exploit. The check does not send mutations, test resolver authorisation, or measure query depth and cost. The discovery agent may import GraphQL schema data even when this check is disabled; that data is recorded in the graph but does not become a finding.

## `reflected-xss`

Default severity: medium.

Applies to GET requests with at least one query parameter. The check skips parameters named `password`, `passwd`, `token`, `csrf`, `authenticity_token`, or `secret`, and parameters beginning with `utm_`. It tests the first three remaining parameters.

The baseline must be HTML and below status 400. The payload is:

```text
"><svg/onload=alert("rt<random>")>
```

A candidate requires the complete payload to appear in the response body and not in the baseline. The evidence includes a short context window around the reflection.

Replay sends the payload again and checks that the raw marker is still present in an HTML response. Confidence is 0.85.

False-positive notes: this is reflection detection, not proof of execution. The browser may block the handler because of CSP, parsing rules, or a framework sanitiser that preserves the text but not the syntax. The report says the finding is based on raw reflection. No JavaScript is executed.

## `sql-injection`

Default severity: high.

Applies to GET requests with at least one query parameter. Parameters named `password`, `passwd`, `token`, `csrf`, `authenticity_token`, `secret`, or `email` are skipped, as are `utm_` parameters. The check tests the first two remaining parameters.

There are two techniques.

Error-based:

1. Take the original parameter value and append a single or double quote.
2. Look for database error signatures such as SQLite `operationalerror`, MySQL syntax errors, PostgreSQL messages, Oracle error codes, or SQL Server driver text.
3. Require the signature to be absent from the baseline.

Boolean differential:

1. Send `<original>' AND '1'='1`.
2. Send `<original>' AND '1'='2`.
3. Normalise whitespace and remove common dynamic tokens.
4. Require the baseline and true responses to be successful, and the true response status to match the baseline.
5. Require similarity(baseline, true) >= 0.97, similarity(true, false) <= 0.92, and a body size gap above 20 bytes.

Replay repeats the matching technique. The error-based validator requires the original signature to be present again. The boolean validator repeats all three requests and requires similarity(baseline, true) >= 0.95, similarity(true, false) <= 0.94, and a size gap above 15 bytes.

False-positive notes: no `UNION`, `SLEEP`, stacked statements, or write statements are sent. Error signatures can appear in benign debug pages, and boolean differences can come from application logic rather than SQL. The replay reduces both risks but does not eliminate them. The confidence values are 0.9 for error-based and 0.72 for boolean candidates before replay.

## `authz-object`

Default severity: high.

Applies to GET endpoints that contain an object identifier. Query keys recognised as identifiers are `id`, `user_id`, `account_id`, `order_id`, `object_id`, and `item`. Path segments consisting of 1-12 digits or a standard UUID are also recognised. Requires at least two authenticated identities.

For each identity that has seen the endpoint:

1. Request the object as that identity (the victim). Skip unless the response is 2xx.
2. Request the object as each other identity (the attacker). Skip unless the response is 2xx.
3. Request the object anonymously. If the anonymous response is 2xx and its body similarity to the victim response is at least 0.92, treat the object as public and skip it.
4. If victim and attacker bodies are at least 0.9 similar and the victim body is at least 40 characters, record a candidate.

The finding records the object reference, victim, attacker, statuses, body similarity, and a short body excerpt. The variant is `attacker->victim`, so two successful directions produce two findings.

Replay requests the object as victim, attacker, and anonymous again. It requires both authenticated responses to be 2xx, similarity >= 0.88, and an anonymous control that is not public. Confidence is 0.82.

False-positive notes: a shared dashboard template, an endpoint that returns the same public catalogue to every signed-in user, or a body that does not identify the owner can still look like cross-account access. The anonymous control removes fully public resources, but it cannot prove ownership semantics. Treat this check as a lead generator that needs evidence review, not as proof of a specific access-control defect.

## Coverage and ordering

`redthread checks` prints the registered checks. `checks.enabled` narrows the set; `checks.disabled` removes entries. An empty `enabled` list means all checks.

The baseline phase orders actions round-robin across checks so that one noisy check cannot consume the whole request budget. The exploration phase uses an MCTS model over the remaining actions. Neither phase changes check thresholds or payloads.

## Adding a check

Implement a subclass of `redthread.checks.base.Check` with:

- `id`, `title`, `severity`, `description`, `remediation`
- optional `cvss`
- `applies(endpoint)`
- optional `enabled(config, identities)`
- `run(ctx, endpoint, identity)`
- `verify(ctx, finding)`

Register the class in `src/redthread/checks/__init__.py`. Keep `run` read-only and keep `verify` specific to the evidence that `run` recorded. Add a unit test for the signal and the replay, and, if possible, an end-to-end case in the lab.
