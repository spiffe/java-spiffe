# Changelog

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

