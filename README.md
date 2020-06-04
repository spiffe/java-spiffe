# JAVA-SPIFFE library

## Overview

The JAVA-SPIFFE library provides functionality to interact with the Workload API to fetch X.509 and JWT SVIDs and Bundles, 
and a Java Security Provider implementation to be plugged into the Java Security architecture. This is essentially 
a X.509-SVID based KeyStore and TrustStore implementation that handles the certificates in memory and receives the updates 
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
 $ ./gradlew build
 
 BUILD SUCCESSFUL 
```

`jar` files are placed in `build/libs` in each module.  
