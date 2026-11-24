# Changelog

## [0.9.0] - 2026-11-24

### Breaking changes

* **JWT audiences:** Empty expected-audience sets could succeed in 0.8.17. All `JwtSvid.parseAndValidate` and `parseInsecure` overloads now throw `IllegalArgumentException`; supply the audience the application expects (#431).
* **Watch retries:** `CANCELLED`, `UNAUTHENTICATED`, `UNIMPLEMENTED` and `FAILED_PRECONDITION` now terminate watches instead of retrying, stopping automatic reconnection and further rotations. Handle termination and restore the watch after resolving the cause. `INVALID_ARGUMENT` was already terminal; initial `PERMISSION_DENIED` still retries with backoff.

### Upgrade considerations

* **Helper truststores:** Before the first 0.9.0 update, move manually installed certificates that must be retained outside the `<trust-domain>.<ASCII numeric index>` alias pattern. Matching certificates can be deleted even if the Helper did not create them. This risk is separate from stale-authority cleanup (#492).
* **TLS peers:** Previously accepted peer certificates can now fail verification, including with `SpiffeIdVerifier.acceptAny()`. Ensure peers meet the X.509-SVID profile and chain to trusted authorities; custom verifiers now run only after chain validation (#510, #511).
* **Helper failures:** `KeyStoreHelper.run(true)` fails on the first watcher error, including `PERMISSION_DENIED` after startup. The CLI closes its client and exits 1, ending retries; resolve the cause and restart the Helper. Initial `PERMISSION_DENIED` before any update still retries with backoff under the default policy (#488, #491).
* **Native transports:** Upgrade separately pinned `grpc-netty-*` artifacts with core. Custom shaded JARs must preserve `META-INF/services/io.spiffe.workloadapi.internal.GrpcChannelProvider`; supplied platform-specific fat JARs already include it (#108, #523).
* **Recovery:** Direct `WorkloadApiClient.watch*` callers can register a new watch after resolving a terminal failure. Built-in sources log the failure and can keep serving cached material after rotations stop; recreate the source and switch its consumers to resume rotations. Closing the old source closes its client, so use a fresh client for the replacement. Permission denial does not automatically invalidate built-in source caches.

### Added

* Add PEM/JWKS bundle serialization and PEM/DER X.509-SVID serialization (#515).
* Publish `java-spiffe-bom` to align library and transport versions.
* Add `SslContextOptions.spiffeIdVerifier` and `SpiffeIdVerifier.acceptAny()`, `acceptId()`, `acceptOneOf()` and `acceptMemberOf()` factories.
* Add `ClientOptions.retryExecutorService` and `RetryHandler.tryScheduleRetry(Runnable)`, retaining `void scheduleRetry(Runnable)`. Clients close supplied retry executors (#79).

### Changed

* Report post-update `PERMISSION_DENIED` immediately, suppress repeated withdrawal notifications until recovery, and report terminal failures when retries cannot continue (#491).
* Consistently report `X509BundleException` for X.509 bundle watches and wrap invalid trust-domain keys in watch-specific exceptions with their causes preserved. Adjust handlers relying on earlier exception types (#491).
* `DefaultWorkloadApiClient.newClient`, `DefaultX509Source.newSource`, `DefaultJwtSource.newSource` and `CachedJwtSource.newSource` no longer write automatically created clients, executors or defaults into supplied options. Getters may remain `null`; reusing options creates independent default clients and executors. Explicitly configure and retain resources to inspect or share them. `KeyStoreHelper.create` still fills in `keyStoreType`, `keyAlias` and `workloadApiClient` on its options; reusing those options shares the client, which Helper `close()` shuts down (#497).

### Fixed

* Enforce X.509-SVID peer leaf requirements for URI SANs, non-root SPIFFE ID paths, CA flags and key usages. Extract SPIFFE IDs only from URI SANs (#510, #511).
* Validate certificate chains before invoking `SpiffeIdVerifier`; invalid chains no longer reach the callback.
* Validate and normalize trust-domain names using ASCII rules independently of the JVM locale (#496).
* Reject watches on closed clients with `IllegalStateException`.
* Propagate asynchronous source initialization errors; preserve watches after rejected post-initialization updates so later rotations can apply (#486).
* Propagate Helper watch failures through `run`, giving CLI failures exit status 1 (#488).
* Safely publish JWT bundle updates across threads; refresh cached JWT-SVIDs without `iat`, and return `null` from `getIssuedAt()` when absent (#429).
* Preserve sub-second retry delays and report failed retry scheduling.
* Accept bracketed IPv6 Workload API addresses; ignore unsupported JWK types while retaining supported bundle authorities (#512).
* Preserve all current Helper bundle authorities and remove stale indexes and absent trust domains. Prepare replacements in memory and write once per update; serialization failures preserve existing files. In-place I/O failures can still leave partial files, and KeyStore/TrustStore writes remain separate (#490, #492).
* Adopt Helper KeyStore/TrustStore changes in memory only after successful writes, and serialize updates per store. Failed updates no longer leak into later writes or block subsequent updates (#490, #525).
* Remove core/native split packages to support the Java module path (#108, #523).

### Dependencies and build

* Update gRPC 1.80.0 → 1.85.1, Netty 4.2.9.Final → 4.2.17.Final, Nimbus JOSE JWT 10.9 → 10.10 and Commons Lang 3.20.0 → 3.22.0. Use Guava 33.8.0-jre and remove Commons Validator.
* Update Gradle 9.4.1 → 9.9.1, the Protobuf plugin 0.9.6 → 0.10.1 and the Maven publishing plugin 0.35.0 → 0.37.0.
* Add japicmp checks for public/protected core and provider APIs, excluding internal and generated gRPC packages, and verify native Netty version alignment. Java 8 source/target compatibility is unchanged.

### Documentation

* Correct source and JWT examples; document initialization timeouts, serialization, verifier configuration and programmatic provider installation.

## [0.8.17] - 2026-04-20

### Fixed

* Enforce SPIFFE-spec-compliant URI SAN validation for X.509-SVID leaf certificates (#421)
* Require a non-root SPIFFE ID path for X.509-SVID leaf certificates, per the SPIFFE spec (#417)
* Tighten SPIFFE ID path validation and segment construction to match the SPIFFE spec (#420)
* Parse SPIFFE IDs case-insensitively and normalize trust domains to lowercase in accordance with the SPIFFE spec (#416)

### Dependency updates

* Bump grpcVersion from 1.79.0 to 1.80.0 (#414)
* Bump com.nimbusds:nimbus-jose-jwt from 10.8 to 10.9 (#423)
* Bump gradle-wrapper from 9.3.1 to 9.4.1 (#412, #419)


## [0.8.16] - 2026-02-25

### Fixed

* Require `spiffe://` prefix when parsing SPIFFE IDs, tightening scheme validation (#398)
* Ensure atomic snapshot of X.509 SVID and bundles in `DefaultX509Source`, preventing torn reads under concurrency (#397)
* Reject null bundles and empty cached SVID lists in core parsing/cache paths (#399)
* Validate presence of JWT audience claim during parsing (#399)

### Dependency updates

* Bump grpcVersion from 1.77.0 to 1.79.0 (#392, #402)
* Bump com.nimbusds:nimbus-jose-jwt from 10.6 to 10.8 (#395, #409)
* Bump gradle-wrapper from 9.2.1 to 9.3.1 (#400, #401)

### Build

* Simplify Dependabot config and group coupled Gradle dependencies (#403)

## [0.8.15] - 2025-12-23

### Fixed

* Fix X509SVID hint deduplication to apply only to non-empty hints (#385)

### Dependency updates

* Remove lombok and replace all annotations with plain java implementations (#377)
* Bump io.netty:netty-transport-native-kqueue to 4.2.9.Final (#381)
* Bump com.google.protobuf to 0.9.6 (#389)

### Build 

* Upgrade to Gradle 9.2.1 and migrate Shadow plugin (#380)
* Remove deprecations and prep for Gradle 10 (#384)
* Add Makefile (#388)


## [0.8.14] - 2025-12-09

### Dependency updates

* Bump io.netty:netty-transport-native-kqueue to 4.2.7.Final (#358)
* Bump org.projectlombok:lombok to 1.18.42 (#362)
* Bump grpcVersion to 1.77.0 (#369)
* Bump com.nimbusds:nimbus-jose-jwt to 10.6 (#366)
* Bump commons-cli:commons-cli to 1.11.0 (#367)
* Bump commons-validator:commons-validator to 1.10.1 (#375)
* Bump org.apache.commons:commons-lang3 to 3.20.0 (#376)

### Build & publishing

* Migrated artifact publishing from OSSRH to the new Sonatype Maven Central Portal.


## [0.8.13] - 2025-07-15

### Dependency updates

* Bump io.netty:netty-transport-native-kqueue to 4.2.2.Final (#332)
* Bump com.nimbusds:nimbus-jose-jwt to 10.3.1 (#335)
* Bump commons-validator:commons-validator to 1.10.0 (#338)
* Bump org.apache.commons:commons-lang3 to 3.18.0 (#339)

## [0.8.12] - 2025-06-05

### Dependency updates

- Bump grpcVersion to 1.73.0 (#327)
- Bump com.nimbusds:nimbus-jose-jwt to 10.3 (#323)
- Bump io.netty:netty-transport-native-kqueue to 4.2.1.Final (#321)
- Bump com.google.protobuf:protobuf-gradle-plugin to 0.9.5 (#314)
- Bump org.projectlombok:lombok to 1.18.38 (#313)

### Documentation

- Add documentation about sslNegotiation config in java-spiffe-provider (#325)

## [0.8.11] - 2024-11-18

### Fixed

- Fix CRLF newline removal in DER format logic for Windows compatibility (#284)

### Dependency updates

- Bump io.netty:netty-transport-native-kqueue from 4.1.114.Final to 4.1.115.Final (#281)
- Bump com.nimbusds:nimbus-jose-jwt from 9.45 to 9.47 (#285)
- Bump org.projectlombok:lombok from 1.18.34 to 1.18.36 (#286)
 

## [0.8.10] - 2024-11-06

### Dependency updates

- Bump jupiterVersion from 5.11.2 to 5.11.3 (#273)
- Bump grpcVersion from 1.68.0 to 1.68.1 (#276)
- Bump com.nimbusds:nimbus-jose-jwt from 9.41.2 to 9.45 (#278)


## [0.8.9] - 2024-10-09

### Dependency updates

- Bump `com.google.protobuf:protoc` to `3.25.5` (#271)

## [0.8.8] - 2024-10-08

### Dependency updates

- Bump `grpcVersion` from 1.66.0 to 1.68.0 (#262) 
- Bump `io.netty:netty-transport-native-kqueue` from 4.1.113.Final to 4.1.114.Final (#265) 
- Bump `com.nimbusds:nimbus-jose-jwt` from 9.41.1 to 9.41.2 in (#266) 

### Changed

- Updated Gradle to version 8.10.2 (#269)

## [0.8.7] - 2024-09-20

### Dependency updates

- Bump `grpcVersion` from 1.62.2 to 1.66.0 (#248)
- Bump `io.netty:netty-transport-native-kqueue` from 4.1.107.Final to 4.1.113.Final (#260)
- Bump `commons-cli:commons-cli` from 1.6.0 to 1.9.0 (#258)
- Bump `com.nimbusds:nimbus-jose-jwt` from 9.37.3 to 9.41.1 (#259)
- Bump `org.apache.commons:commons-lang3` from 3.14.0 to 3.17.0 (#255)
- Bump `org.projectlombok:lombok` from 1.18.30 to 1.18.34 (#253)
- Bump `commons-validator:commons-validator` from 1.8.0 to 1.9.0 (#251)
- Bump `jupiterVersion` from 5.10.2 to 5.11.0 (#254)

## [0.8.6] - 2024-03-04

### Dependency updates

- Bump `com.google.protobuf:protoc` from 3.25.2 to 3.25.3 (#218)
- Bump `io.grpc:grpc-protobuf`, `io.grpc:grpc-stub`, `io.grpc:grpc-netty`, `io.grpc:grpc-netty-shaded`,
  and `io.grpc:protoc-gen-grpc-java` from 1.61.1 to 1.62.2 (#222)
- Bump `io.netty:netty-transport-native-kqueue` from 4.1.106.Final to 4.1.107.Final (#205)

### CI/CD Improvements

Automated build and publish process via GitHub Actions.

## [0.8.5] - 2024-14-02

### Added

- Docker container and CI workflow for `java-spiffe-helper` (#187)

### Changed

- Updated Gradle to version 8.5 (#201)
- Various enhancements in `java-spiffe-helper` (#199)

### Fixed

- Addressed a Fat Jar Assembly issue. (#198)

### Dependency updates

- Bump `io.grpc:grpc-protobuf` and  `io.grpc:grpc-stub` from 1.54.0 to 1.61.1 (#202)
- Bump `commons-validator:commons-validator` from 1.7. to 1.8.0 (#197)
- Bump `commons-cli:commons-cli` from 1.5.0 to 1.6.0 (#196)
- Bump `com.google.protobuf:protoc` from 3.21.12 to 3.25.2 (#193)
- Bump `io.netty:netty-transport-native-kqueue` from 4.1.91.Final to 4.1.106.Final (#192)
- Bump `org.apache.commons:commons-lang3` from 3.12.0 to 3.14.0 (#189)
- Bump `com.nimbusds:nimbus-jose-jwt` from 9.31 to 9.37.3 (#184)
- Bump `org.projectlombok:lombok` from 1.18.26 to 1.18.30 (#170)
- Bump `com.google.protobuf:protobuf-gradle-plugin` from 0.9.2 to 0.9.4 (#153)

## [0.8.4] - 2023-04-14

### Dependencies updates

- Bump `commons-cli:commons-cli` from 1.4 to 1.5.0 (#124)
- Bump `com.google.osdetector` from 1.6.2 to 1.7.3 (#125)
- Bump `org.apache.commons:commons-lang3` from 3.11 to 3.12.0 (#129)
- Bump `org.projectlombok:lombok` from 1.18.20 to 1.18.26 (#128)

## [0.8.3] - 2023-04-13

### Added

- A `JwtSource` implementation,`CachedJwtSource`, that caches the JWT SVIDs based on their subjects and audiences (#116)
- Support for the `hint` field in the SVIDs retrieved by Workload API client (#114)

