# Security policy

## Supported versions

redthread is alpha software. Security fixes are applied to the current `0.1.x` line. Older snapshots are not maintained.

## Reporting a vulnerability in redthread

Do not open a public issue containing:

- credentials,
- target hostnames or internal URLs,
- response data,
- evidence files from a real assessment,
- exploitation details for a production system.

Use the repository's private security advisory or the maintainer contact listed in the project hosting settings. If neither is available, contact a maintainer directly and ask for a private channel before sending details.

Include:

- the affected version or commit,
- a minimal reproduction,
- the impact you believe is possible,
- whether the issue affects scope enforcement, credential handling, report redaction, or the target rather than the tool.

You should receive an acknowledgement within a few days. There is no bug bounty programme.

## Reporting a vulnerability in a target

redthread is a testing tool, not a disclosure service. If a scan suggests a vulnerability in a system you do not own, do not test further. Follow the target's security policy or a coordinated disclosure process.

The project does not accept reports about third-party systems.

## Safe testing

Before running the tool:

- confirm written authorization,
- read `docs/safety.md`,
- start with a loopback lab or a disposable test environment,
- set a request budget and rate limit,
- keep the stop file path available,
- decide how run artifacts will be stored and shared.

The bundled lab is intentionally vulnerable and must stay bound to loopback.
