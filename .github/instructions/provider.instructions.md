---
applyTo: "**/java-spiffe-provider/**"
---

This code integrates with Java Security Provider mechanics.

Be careful with:
- provider semantics
- keystore/truststore behavior
- initialization order
- exception clarity
- backward compatibility

Specifically check:
- provider and algorithm registration, and any reliance on registration order or position
- `KeyManager` and `TrustManager` behavior when no SVID or bundle is available yet
- SPIFFE ID acceptance checks in the trust manager, including how the accepted-ID list is sourced and refreshed
- separation between identity material in the keystore and trust material in the truststore
- static or global provider state that can leak across callers, classloaders, or tests
- system property and configuration defaults that silently change a trust decision

Do not suggest changes that make provider behavior more implicit or harder to reason about. Behavioral provider changes need tests for initialization failure and for rejection of untrusted peer identities; this does not apply to docs, comments, or non-behavioral cleanup.