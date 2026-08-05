---
applyTo: "**/io/spiffe/workloadapi/**"
---

This code owns Workload API clients and the long-lived `X509Source` and `JwtSource` objects. Use the official Workload API standard when a finding depends on spec semantics:
https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md

Check:
- fetch versus watch semantics, and what callers observe before the first update
- whether an update replaces prior state atomically, without exposing a partial view
- stale data after a failed update, reconnect, cancellation, or close
- reconnect and retry behavior, including whether errors reach the caller or are silently swallowed
- stream observer lifecycle, executor shutdown, and resource cleanup on close
- thread safety of shared source objects and their internal caches

Flag any change that lets a closed or failed source keep serving identities, or that turns a hard failure into a silent fallback.

Lifecycle and concurrency changes need deterministic tests. Do not accept new tests that depend on sleeps for timing.
