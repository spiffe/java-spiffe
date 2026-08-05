---
applyTo: "**/io/spiffe/svid/**,**/io/spiffe/bundle/**"
---

This code parses and validates X.509-SVIDs, JWT-SVIDs, and bundles. Use the official SPIFFE standards when a finding depends on spec semantics:
- https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md
- https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md
- https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md
- https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md

For X.509-SVIDs, check:
- URI SAN extraction and behavior when there are zero or multiple URI SANs
- chain ordering assumptions and leaf versus CA semantics
- bundle selection by trust domain, and behavior on trust-domain mismatch
- expiry and malformed certificate handling

For JWT-SVIDs, check:
- audience, subject, issuer, expiry, and not-before validation
- algorithm and key ID handling, and how a key is selected from the bundle
- behavior when the bundle has multiple, missing, or unusable keys
- that signature verification cannot be skipped for any token shape

For bundles, check:
- parsing of incomplete or inconsistent key material
- bundle replacement versus merge semantics on update
- federation and cross-trust-domain lookup behavior

Flag validation that is reordered, skipped on a fast path, or turned into a warning. Every validation change needs a negative test with malformed material.

If a change under `io/spiffe/internal/` supports SVID, JWT, or bundle parsing (for example key or algorithm handling used during validation), apply this same checklist to it.
