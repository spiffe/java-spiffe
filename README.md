# JAVA-SPIFFE library

<a href='https://travis-ci.org/spiffe/java-spiffe.svg?branch=master'><img src='https://travis-ci.org/spiffe/java-spiffe.svg?branch=master'></a>
[![Coverage Status](https://coveralls.io/repos/github/spiffe/java-spiffe/badge.svg?branch=master)](https://coveralls.io/github/spiffe/java-spiffe?branch=master)

## Overview

The JAVA-SPIFFE library provides functionality to interact with the Workload API to fetch X.509 and JWT SVIDs and Bundles, 
and a Java Security Provider implementation to be plugged into the Java Security architecture. This is essentially 
an X.509-SVID based KeyStore and TrustStore implementation that handles the certificates in memory and receives the updates 
asynchronously from the Workload API. The KeyStore handles the Certificate chain and Private Key to prove identity 
in a TLS connection, and the TrustStore handles the trusted bundles (supporting federated bundles) and performs 
peer's certificate and SPIFFE ID verification. 

This library is composed of three modules:

[java-spiffe-core](java-spiffe-core/README.md): core functionality to interact with the Workload API, and to process and validate 
X.509 and JWT SVIDs and bundles.

[java-spiffe-provider](java-spiffe-provider/README.md): Java Provider implementation.

[java-spiffe-helper](java-spiffe-helper/README.md): Helper to store X.509 SVIDs and Bundles in Java Keystores in disk.

**Supports Java 8+**

### Build the JARs

```
 $ ./gradlew assemble
 BUILD SUCCESSFUL 
```

All `jar` files are placed in `build/libs` folder.  
