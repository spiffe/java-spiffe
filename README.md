# JAVA-SPIFFE library

## Overview

The JAVA-SPIFFE library provides functionality to fetch SVIDs Bundles from a Workload API

## SPIFFE Workload API ClientExample

The `WorkloadAPIClient` provides the method `fetchX509SVIDs` that fetches SVIDs from the Workload API,
using a BlockingStub and an very basic ExponentialBackoff Policy.

The channel is configured based on the Address (tcp or unix socket) and the OS detected.

## Use
```
WorkloadAPIClient workloadAPIClient = new WorkloadAPIClient("/tmp/agent.sock");
List<X509SVID> svids = workloadAPIClient.fetchX509SVIDs();
for (X509SVID svid : svids) {
    System.out.println("Spiffe ID fetched " + svid.getSpiffeId());
}
```

### Running the example

Required:
* A running Spire server. [HowTo](https://github.com/spiffe/spire#installing-spire-server-and-agent)
* A Spire entry that matches this application.
```
cmd/spire-server/spire-server entry create \
-spiffeID spiffe://example.org/host/workload \
-parentID spiffe://example.org/host \
-selector unix:uid:1000
```

To start the Java server you can run `./gradlew run`

```
$ ./gradlew run

> Task :run
[main] INFO ClientExample - Spiffe ID fetched: spiffe://example.org/host/workload

BUILD SUCCESSFUL in 1s

```

### Generating the JAR 

```
./gradlew build
```

The jar file `java-spiffe-0.1-SNAPSHOT.jar` is generated in folder `libs`.