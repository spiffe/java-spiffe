# Java SPIFFE Library

[![Build Status](https://github.com/spiffe/java-spiffe/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/spiffe/java-spiffe/actions/workflows/build.yml?query=branch%3Amain)
[![Coverage Status](https://coveralls.io/repos/github/spiffe/java-spiffe/badge.svg)](https://coveralls.io/github/spiffe/java-spiffe?branch=main)

## Overview

The JAVA-SPIFFE library provides functionality to interact with the Workload API to fetch X.509 and JWT SVIDs and Bundles, 
and a Java Security Provider implementation to be plugged into the Java Security architecture. This is essentially 
an X.509-SVID based KeyStore and TrustStore implementation that handles the certificates in memory and receives the updates 
asynchronously from the Workload API. The KeyStore handles the Certificate chain and Private Key to prove identity 
in a TLS connection, and the TrustStore handles the trusted bundles (supporting federated bundles) and performs 
peer's certificate and SPIFFE ID verification. 

This library contains three modules:

* [java-spiffe-core](java-spiffe-core/README.md): Core functionality to interact with the Workload API, and to process and validate 
X.509 and JWT SVIDs and bundles.

* [java-spiffe-provider](java-spiffe-provider/README.md): Java Provider implementation.

* [java-spiffe-helper](java-spiffe-helper/README.md): Helper to store X.509 SVIDs and Bundles in Java Keystores in disk.

**Supports Java 8+**

Download
--------

The JARs can be downloaded from [Maven Central](https://search.maven.org/search?q=g:io.spiffe%20AND%20v:0.8.17). 

The dependencies can be added to `pom.xml`

To import the `java-spiffe-provider` component: 
```xml
<dependency>
  <groupId>io.spiffe</groupId>
  <artifactId>java-spiffe-provider</artifactId>
  <version>0.8.17</version>
</dependency>
```
The `java-spiffe-provider` component imports the `java-spiffe-core` component.

To just import the `java-spiffe-core` component:
```xml
<dependency>
  <groupId>io.spiffe</groupId>
  <artifactId>java-spiffe-core</artifactId>
  <version>0.8.17</version>
</dependency>
```

Using Gradle:

Import `java-spiffe-provider`:
```gradle
implementation group: 'io.spiffe', name: 'java-spiffe-provider', version: '0.8.17'
```

Import `java-spiffe-core`:
```gradle
implementation group: 'io.spiffe', name: 'java-spiffe-core', version: '0.8.17'
```

### MacOS Support

#### x86 Architecture

In case run on a osx-x86 architecture, add to your `pom.xml`:

```xml

<dependency>
  <groupId>io.spiffe</groupId>
  <artifactId>grpc-netty-macos</artifactId>
  <version>0.8.17</version>
  <scope>runtime</scope>
</dependency>
```

Using Gradle:
```gradle
runtimeOnly group: 'io.spiffe', name: 'grpc-netty-macos', version: '0.8.17'
```

#### Aarch64 (M1) Architecture

If you are running the aarch64 architecture (M1 CPUs), add to your `pom.xml`:

```xml

<dependency>
  <groupId>io.spiffe</groupId>
  <artifactId>grpc-netty-macos-aarch64</artifactId>
  <version>0.8.17</version>
  <scope>runtime</scope>
</dependency>
```

Using Gradle:

```gradle
runtimeOnly group: 'io.spiffe', name: 'grpc-netty-macos-aarch64', version: '0.8.17'
```

*Caveat: not all OpenJDK distributions are aarch64 native, make sure your JDK is also running
natively*


## Java SPIFFE Helper

The `java-spiffe-helper` module manages X.509 SVIDs and Bundles in Java Keystores.

### Docker Image

Pull the `java-spiffe-helper` image from `ghcr.io/spiffe/java-spiffe-helper:0.8.17`.

For more details, see [java-spiffe-helper/README.md](java-spiffe-helper/README.md).

## Build the JARs

On Linux or MacOS, run:

```
 $ ./gradlew assemble
 BUILD SUCCESSFUL 
```

All `jar` files are placed in `build/libs` folder.  

### Binary compatibility

`./gradlew check` (and `./gradlew build`) runs japicmp for `java-spiffe-core` and
`java-spiffe-provider`. It compares each module's regular JAR against its latest
stable Maven Central release, selecting versions of the form `major.minor.patch`
and rejecting prereleases. Helper, native transport, test-fixture and shaded JARs
are not compared. Dependencies are resolved separately on each side to look up
referenced types, not treated as APIs belonging to this project.

The gate checks public and protected APIs, including synthetic bridge methods,
and excludes the `internal` and generated `grpc` packages excluded from Javadoc.
Binary-incompatible changes fail the build; compatible additions and source-only
incompatibilities do not. Text and HTML reports are written to
`<module>/build/reports/japicmp/`, including when an incompatibility fails the task.

Run just the compatibility checks locally (no SPIRE agent is required):

```sh
./gradlew :java-spiffe-core:japicmp :java-spiffe-provider:japicmp
```

For a maintenance branch, pin the release from which that branch was developed:

```sh
./gradlew check -PbaselineVersion=0.8.17
```

The default baseline refreshes Maven metadata on each invocation. Gradle can reuse
a successful comparison when its API inputs are unchanged; changes to either
JAR, its dependencies or the comparison configuration invalidate that result.
Use a pinned baseline and `--offline` when the required artifacts are already
cached. Resolution errors fail the build rather than silently skipping the check.
For a first-ever release with no published baseline, explicitly use
`-PbaselineVersion=none`; this skips the comparison with a warning. Do not use
that opt-out to accept breaking changes in an existing library.

#### Intentional breaking changes

Add the narrowest possible exclusion to the affected module's `japicmp` task,
with a rationale and a **Breaking changes** entry in `CHANGELOG.md`. For example:

```groovy
tasks.named('japicmp') {
    methodExcludes.add('io.spiffe.example.Example#method(java.lang.String)')
}
```

Use `fieldExcludes` for individual fields. Reserve `classExcludes` for deliberate
removal of an entire type; avoid package-wide exclusions or disabling failure.
Method signatures include parameter types but not return types, so an exclusion
also hides future changes to that method. Remove exclusions once the baseline
contains the accepted change. Document whether consumers need to recompile or
migrate; deprecation alone does not make an ABI break compatible.

#### Testing the gate

```sh
./gradlew binaryCompatibilityTest
```

These Gradle TestKit tests compile small Java APIs and publish them to temporary
local Maven repositories. They exercise compatible additions, removed public and
protected methods, builder return-type changes, stable baseline selection,
version pinning, missing baselines, narrow exclusions and up-to-date invalidation.
They also compare the published 0.8.14 and 0.8.15 core JARs and assert that the
`X509SourceOptionsBuilder` regression is detected. This historical test downloads
those releases from Maven Central; all tests use the project's Gradle version
and the JDK running the build. To run only the historical regression:

```sh
./gradlew binaryCompatibilityTest --tests '*detectsPublishedBuilderRegressionFrom0814To0815'
```

#### Jars that include all dependencies 

For the module [java-spiffe-provider](java-spiffe-provider), a fat jar is generated with the classifier `-all-[os-classifier]`.

For the module [java-spiffe-helper](java-spiffe-helper), a fat jar is generated with the classifier `[os-classifier]`.

Based on the OS where the build is run, the `[os-classifier]` will be:

* `-linux-x86_64` for Linux
* `-osx-x86_64` for MacOS with x86_64 architecture
* `-osx-aarch64` for MacOS with aarch64 architecture (M1)
