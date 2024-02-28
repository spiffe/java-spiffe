# Java SPIFFE Library

[![Build Status](https://github.com/spiffe/java-spiffe/actions/workflows/pr_build.yml/badge.svg)](https://github.com/spiffe/java-spiffe/actions/workflows/pr_build.yml)
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

The JARs can be downloaded from [Maven Central](https://search.maven.org/search?q=g:io.spiffe%20AND%20v:0.8.5). 

The dependencies can be added to `pom.xml`

To import the `java-spiffe-provider` component: 
```xml
<dependency>
  <groupId>io.spiffe</groupId>
  <artifactId>java-spiffe-provider</artifactId>
  <version>0.8.5</version>
</dependency>
```
The `java-spiffe-provider` component imports the `java-spiffe-core` component.

To just import the `java-spiffe-core` component:
```xml
<dependency>
  <groupId>io.spiffe</groupId>
  <artifactId>java-spiffe-core</artifactId>
  <version>0.8.5</version>
</dependency>
```

Using Gradle:

Import `java-spiffe-provider`:
```gradle
implementation group: 'io.spiffe', name: 'java-spiffe-provider', version: '0.8.5'
```

Import `java-spiffe-core`:
```gradle
implementation group: 'io.spiffe', name: 'java-spiffe-core', version: '0.8.5'
```

### MacOS Support

#### x86 Architecture

In case run on a osx-x86 architecture, add to your `pom.xml`:

```xml

<dependency>
  <groupId>io.spiffe</groupId>
  <artifactId>grpc-netty-macos</artifactId>
  <version>0.8.5</version>
  <scope>runtime</scope>
</dependency>
```

Using Gradle:
```gradle
runtimeOnly group: 'io.spiffe', name: 'grpc-netty-macos', version: '0.8.5'
```

#### Aarch64 (M1) Architecture

If you are running the aarch64 architecture (M1 CPUs), add to your `pom.xml`:

```xml

<dependency>
  <groupId>io.spiffe</groupId>
  <artifactId>grpc-netty-macos-aarch64</artifactId>
  <version>0.8.5</version>
  <scope>runtime</scope>
</dependency>
```

Using Gradle:

```gradle
runtimeOnly group: 'io.spiffe', name: 'grpc-netty-macos-aarch64', version: '0.8.5'
```

*Caveat: not all OpenJDK distributions are aarch64 native, make sure your JDK is also running
natively*


## Java SPIFFE Helper

The `java-spiffe-helper` module manages X.509 SVIDs and Bundles in Java Keystores.

### Docker Image

Pull the `java-spiffe-helper` image from `ghcr.io/spiffe/java-spiffe-helper:0.8.5`.

For more details, see [java-spiffe-helper/README.md](java-spiffe-helper/README.md).

## Build the JARs

On Linux or MacOS, run:

```
 $ ./gradlew assemble
 BUILD SUCCESSFUL 
```

All `jar` files are placed in `build/libs` folder.  

#### Jars that include all dependencies 

For the module [java-spiffe-provider](java-spiffe-provider), a fat jar is generated with the classifier `-all-[os-classifier]`.

For the module [java-spiffe-helper](java-spiffe-helper), a fat jar is generated with the classifier `[os-classifier]`.

Based on the OS where the build is run, the `[os-classifier]` will be:

* `-linux-x86_64` for Linux
* `-osx-x86_64` for MacOS with x86_64 architecture
* `-osx-aarch64` for MacOS with aarch64 architecture (M1)
