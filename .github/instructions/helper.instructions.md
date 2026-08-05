---
applyTo: "**/java-spiffe-helper/**"
---

This module writes SVIDs and bundles into Java keystores and truststores on disk.

Check:
- keystore versus truststore separation, so private keys never land in the truststore
- entry aliasing and whether a refresh replaces, duplicates, or orphans prior entries
- file paths, permissions, and passwords read from configuration
- behavior when the Workload API is unavailable at startup or during refresh
- shutdown behavior and cleanup of partially written stores

Flag passwords or key material that reach logs or exception messages, and refresh paths that leave a store in a partially updated state.

Helper concerns must not leak into `java-spiffe-core` APIs.
