---
applyTo: "**/io/spiffe/**,**/java-spiffe-provider/**,**/java-spiffe-helper/**"
---

This code makes trust decisions. Review it as security-sensitive.

For spec-sensitive security findings, use the official SPIFFE standards as the source of truth when accessible:
https://github.com/spiffe/spiffe/tree/main/standards

Prioritize findings in this order:
1. Invalid identities, SVIDs, bundles, or JWTs that could be accepted.
2. Valid material rejected in a way that breaks existing callers.
3. Trust-domain, issuer, audience, key, or bundle confusion.
4. Stale or partially applied updates that remain usable for authorization.
5. Identity material (private keys, SVIDs) mixed with trust material (bundles, CA certs).
6. Failures that do not fail closed, or that swallow the original cause.

Also flag:
- Private keys, tokens, passwords, keystores, or truststores written to logs, exceptions, temp files, or test fixtures.
- Validation moved behind a flag, cached, or short-circuited.
- New defaults that make a trust decision implicitly.

Do not report generic hardening advice that is unrelated to the diff.
