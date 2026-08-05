---
applyTo: "**/build.gradle,**/settings.gradle,**/gradle.properties,**/module-info.java"
---

This is a multi-module Gradle build (`java-spiffe-core`, `java-spiffe-provider`, `java-spiffe-helper`) published to Maven Central, targeting Java 8 source/target compatibility.

Check:
- dependency version bumps for known CVEs, license changes, and transitive impact across modules
- the pinned relationship between the gRPC version and the shaded Netty version in the root `build.gradle`; a gRPC bump without a matching Netty check is a likely bug
- new dependencies added to a module that should stay dependency-light (especially `java-spiffe-core`)
- changes that would raise the minimum Java version, since the project targets Java 8
- `module-info.java` changes for exported/required packages that would change the public module surface
- publishing configuration (`com.vanniktech.maven.publish`, signing, artifact coordinates) for accidental changes to what gets published or how it is versioned

Flag any dependency or build change without a stated reason, and any change that could silently alter what is published to Maven Central.
