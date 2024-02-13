# Changelog

## [0.8.5] - 2024-14-02

### Added

- Docker container and CI workflow for `java-spiffe-helper` (#187)

### Changed

- Updated Gradle to version 8.5 (#201)
- Various enhancements in `java-spiffe-helper` (#199)

### Fixed

- Addressed a Fat Jar Assembly issue. (#198)

### Dependencies updates

- Bump `grpcVersion` from 1.54.0 to 1.61.1 (#202)
- Bump `commons-validator:commons-validator` from 1.7. to 1.8.0 (#197)
- Bump `commons-cli:commons-cli` from 1.5.0 to 1.6.0 (#196)
- Bump `com.google.protobuf` from 3.21.12 to 3.25.2 (#193)
- Bump `io.netty:netty-transport-native-kqueue` from 4.1.91.Final to 4.1.106.Final (#192)
- Bump `org.apache.commons:commons-lang3` from 3.13.0 to 3.14.0 (#189)
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

