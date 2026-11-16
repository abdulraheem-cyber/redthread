# Safety

redthread makes real HTTP requests. It is built for authorised testing, not for browsing or reconnaissance against systems you do not control.

## Intended use

Suitable uses:

- A local lab or disposable test environment.
- A CI job against an application you own, with a dedicated test account and test data.
- An authorised assessment where the scope, methods, rate, and stop conditions have been agreed in writing.

Unsuitable uses:

- Internet-wide scanning.
- Checking whether a third-party site is vulnerable.
- Production testing without an approved change window and a rollback plan.
- Using the output as proof of exploitability without reviewing the evidence.

## Authorization model

Scope is deny-by-default. Every request is checked against the URL allowlist and exclude patterns before it is sent.

Loopback targets (`localhost`, `*.localhost`, `127.0.0.0/8`, and `::1`) can run without the authorization flag. Any other seed requires:

```toml
[run]
authorized = true
```

This flag is an assertion by the operator. redthread cannot verify that you have permission, that the target is a test system, or that the rules of engagement cover the chosen checks. Setting it does not make an unauthorised test authorised.

A seed is the URL in `scope.include`. If you list multiple seeds, each one is checked. Redirects are followed only when the new URL also passes the scope check. URLs with embedded credentials are rejected.

## Request methods

The only allowed methods are GET, HEAD, OPTIONS, and POST.

POST is disabled by default. When `run.allow_post = true`, it is used for:

- Submitting a form login.
- Sending a GraphQL introspection query.

Checks do not send GraphQL mutations, create or delete resources, upload files, change passwords, or submit arbitrary forms. The discovery agent records forms but does not submit them except through the configured authentication flow.

GET is treated as safe, but the scanner cannot know whether a particular application has side effects on GET. Exclude risky paths explicitly. The discovery filter skips paths containing `logout`, `logoff`, `signout`, `sign-out`, `delete`, `remove`, `destroy`, `reset`, `revoke`, or `unsubscribe`, but that pattern is a guardrail, not a complete model of your application.

The optional nmap integration is outside the HTTP request path. It runs the configured binary against the hostnames of the seeds. It does not understand URL path prefixes in the scope, so a seed such as `https://example.test/app` results in an nmap scan of the whole host. Leave `integrations.nmap_enabled` false unless that is intended.

## Technical limits

A run is bounded by:

- `run.max_requests`
- `run.max_runtime_seconds`
- `run.rate_limit`
- `run.max_baseline_actions`
- `run.max_explore_actions`
- `run.stagnant_limit`
- `run.workers`

The rate limiter spaces request starts globally across all identities. It does not guarantee that only one request is in flight, because `workers` baseline actions can overlap. Slow responses can extend a run beyond `max_runtime_seconds` by up to the HTTP timeout (12 seconds per request) because the limit is checked when a new request starts.

## Stop file

The default stop file is `.redthread.stop` relative to the config file. The orchestrator checks it before creating a run directory. The budget checks it again during each request, at most once per second.

Create the file to stop the current run:

```console
echo stop > .redthread.stop
```

The file contents are used as the stop reason. A run that stops this way still writes a partial report and records the reason. Delete the file before starting the next run, otherwise the next run stops immediately.

## What the checks send

- Header checks send ordinary GET requests.
- CORS checks send `Origin: https://redthread.invalid`.
- Open redirect checks send absolute URLs on `redthread.invalid` and do not follow redirects.
- XSS checks send an alert payload designed to reveal raw reflection.
- SQL injection checks send quote characters and boolean conditions. They do not send writes or time delays.
- BOLA checks request object URLs as multiple identities and anonymously.
- GraphQL introspection sends a read-only schema query.

The `.invalid` top-level domain is reserved by RFC 2606 and cannot resolve to a real service. This keeps probe payloads from directing traffic to a third party even if an application reflects or redirects them.

## Output sensitivity

Reports contain evidence, including response excerpts. They are not guaranteed to be free of personal data, business data, or internal hostnames. A run directory should be handled like test output from the target system.

The audit log is more conservative:

- Bodies are not stored.
- Cookies, authorization headers, and API keys are not stored.
- Sensitive query values are redacted.
- Cookie names may be recorded during authentication.

Sensitive query names include password, passwd, pass, pwd, token, secret, API key, auth, session, sig, code, and key. Redaction is name-based. A secret placed in an unusual parameter name, a URL path, or a response body can still appear in the report.

## Language model use

The LLM is optional and off by default. When enabled, it receives:

- scope include and exclude entries,
- up to 60 endpoint summaries with redacted URLs, parameter names, tags, identities, and truncated notes,
- active check descriptions,
- up to 12 validated finding summaries.

It does not receive credentials, cookies, response bodies, request bodies, or raw evidence.

The provider may log prompts. If endpoint paths, parameter names, or notes are sensitive, do not enable the LLM or point `llm.base_url` at an internal gateway.

Model output is treated as untrusted input and cannot:

- introduce a new check,
- supply a payload to a check,
- request a method outside GET, HEAD, or OPTIONS,
- bypass scope, exclude patterns, or the destructive-path filter,
- declare or validate a finding.

A model request that fails or returns invalid JSON is ignored and the deterministic planner continues.

## Demo lab

`labs/labshop.py` is deliberately vulnerable. It binds to `127.0.0.1` by default and must not be exposed to a network or the internet. The accounts and passwords in the lab and example config are test fixtures, not secrets.

## Review expectations

"Validated" means the evidence was reproduced by a second request. It does not mean a human reviewed the finding, that the issue is exploitable in every configuration, or that it is the most important issue on the target.

The checks use heuristics. A BOLA finding can be a shared page template. An SQL injection finding can be an error page that mentions a database. An XSS finding can be a reflected string that a browser would never execute. Report quality depends on evidence review.

## Standards

The project is designed against the Tier 1 control ideas in OWASP APTS: scope, authorization, rate limiting, auditability, replay, and evidence retention. It is not certified against APTS, has not completed a conformance assessment, and does not provide a compliance programme. Any statement that it "meets APTS" would be inaccurate.

## Reporting a problem in redthread

If you find a security issue in the tool itself, follow `SECURITY.md` rather than opening a public issue with target data.
