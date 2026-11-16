# Prior art

redthread is assembled from well-established ideas. The goal is not to claim a new class of vulnerability detection. It is to show a small, inspectable system where planning, deterministic checks, replay, and evidence retention fit together.

## Scanners

**OWASP ZAP** is the closest reference for the overall shape. It has a spider, passive and active scan rules, authentication handling, an API, and a mature rule set. redthread borrows the baseline-scan idea and the practice of recording request evidence. It is much smaller, has no proxy, no browser-based spider, and no rule marketplace.

**Burp Suite** is an interactive testing platform. Its strength is the analyst workflow: intercepting requests, repeating them with modifications, comparing responses, and using extensions. redthread is automated and headless. It does not try to replace interactive exploration; it tries to make a bounded subset repeatable.

**Nuclei** uses YAML templates to describe requests and matchers. It has a much larger community rule set than redthread and is better suited to broad technology fingerprinting and known-CVE checks. redthread keeps checks in Python so the detection and the replay validator live in the same class. That makes the validation contract explicit, but it also makes the check set smaller and harder to contribute.

**Nikto** focuses on web server misconfiguration and known files. Its header and server checks overlap with redthread's `headers` check. redthread does not attempt its breadth of server fingerprints or path lists.

**Commercial continuous scanning products** combine scheduled scans, asset inventories, authentication, and dashboards. redthread has a `watch` command, but it is a loop around a single config, not an asset management platform. It has no multi-tenant model, no scheduling service, and no long-term trend database.

## Graphs

Graph-based security tools model relationships between identities, permissions, and resources. BloodHound is the best-known example in Active Directory. redthread applies the same general idea to a web crawl: identities, endpoints, documents, tags, hypotheses, and findings become nodes and edges. The graph is deliberately local and small. It is not an attack-path engine, and the current queries are simple lookups and neighbour lists.

The SQLite graph is a convenience for evidence and planning, not a graph database. Neo4j export exists because some teams already use a graph platform, not because the tool needs one.

## Planning

Monte Carlo tree search is a standard planning technique. redthread uses a very small implementation to order known check actions. The rollouts are model-based; they do not send requests to the target. This is closer to a bandit-style scheduler with a tree than to a full planning system.

The optional language model is used as a proposal mechanism. The idea of letting a model suggest next actions, while a deterministic policy enforces scope and methods, is common in current agent tooling. redthread's specific constraint is that the model cannot author a request payload or declare a finding.

## Checks

The individual checks are conventional:

- Missing security headers follow the OWASP Secure Headers Project guidance.
- CORS checks use the standard Origin reflection test.
- Open redirect checks use an external reserved domain.
- GraphQL introspection is a standard schema query.
- Reflected XSS uses a benign alert payload.
- SQL injection uses error signatures and boolean differentials, both classic techniques.
- Object-level authorisation follows the idea behind OWASP API Security Top 10 API1:2023, broken object level authorization.

None of these techniques are new. The value, if any, is in the consistency of the evidence and replay.

## Replay validation

The practice of confirming a scanner finding with a second request is not new. Many scanners have "verify" or "recheck" options, and analysts routinely repeat a request by hand. redthread makes replay part of the finding lifecycle and keeps rejected candidates visible. The label `validated` is intentionally narrow: evidence reproduced, not issue reviewed.

## Standards and frameworks

OWASP's Autonomous Penetration Testing Standard (APTS) describes governance requirements for autonomous penetration testing platforms, including scope enforcement, safety controls, auditability, and reporting. redthread is designed against the Tier 1 control ideas, but it has not been assessed against the standard and is not certified. The project does not implement the organisational controls, independence, or evidence requirements that a conformance claim would need.

The same caution applies to any other framework. A check that maps to a category is not proof that the category is covered. A report field is not an audit opinion.

## References

- OWASP ZAP: https://www.zaproxy.org/
- Burp Suite: https://portswigger.net/burp
- Nuclei: https://github.com/projectdiscovery/nuclei
- Nikto: https://github.com/sullo/nikto
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- OWASP API Security Top 10, API1:2023: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- OWASP APTS: https://owasp.org/APTS/
