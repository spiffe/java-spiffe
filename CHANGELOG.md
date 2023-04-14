# Changelog

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

