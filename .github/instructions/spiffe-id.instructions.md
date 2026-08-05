---
applyTo: "**/io/spiffe/spiffeid/**"
---

This package implements SPIFFE ID and trust domain semantics. Treat the official SPIFFE ID standard as ground truth:
https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md

Check that changes preserve:
- scheme `spiffe`, compared case-insensitively
- trust domain taken from the authority host, canonicalized to lowercase
- rejection of userinfo, port, query, fragment, and percent-encoding
- rejection of empty hosts and IPv6 authority forms
- path case sensitivity, with no silent normalization of segments
- rejection of empty, `.`, and `..` segments and trailing slashes
- equality and canonical string rendering staying consistent with each other

Flag any change that makes parsing more permissive, or that adds strictness beyond the spec without calling it out as a deliberate compatibility change.

Parsing changes need both accepting and rejecting test cases.
