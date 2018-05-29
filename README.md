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
* A running Spire server and agent. [HowTo](https://github.com/spiffe/spire#installing-spire-server-and-agent)
* An entry in the registry that matches this application:
```
cmd/spire-server/spire-server entry create \
-spiffeID spiffe://example.org/workload \
-parentID spiffe://example.org/host \
-selector unix:uid:1000
```

To start the Java server you can run `./gradlew run`

```
$ ./gradlew run

> Task :run
[main] INFO ClientExample - Spiffe ID fetched: spiffe://example.org/workload

BUILD SUCCESSFUL in 1s

```

Output example when it fails in 4 attempts and succeeds on the 5 attempt after waiting following an exponential backoff policy:

```
$ ./gradlew run

[main] INFO spiffe.api.svid.util.ExponentialBackOff - Attempt no. 1
[main] INFO spiffe.api.svid.util.ExponentialBackOff - Error UNAVAILABLE: io exception
[main] INFO spiffe.api.svid.util.ExponentialBackOff - Sleeping for 2000ms
[main] INFO spiffe.api.svid.util.ExponentialBackOff - Attempt no. 2
[main] INFO spiffe.api.svid.util.ExponentialBackOff - Error UNAVAILABLE: io exception
[main] INFO spiffe.api.svid.util.ExponentialBackOff - Sleeping for 4000ms
[main] INFO spiffe.api.svid.util.ExponentialBackOff - Attempt no. 3
[main] INFO spiffe.api.svid.util.ExponentialBackOff - Error UNAVAILABLE: io exception
[main] INFO spiffe.api.svid.util.ExponentialBackOff - Sleeping for 8000ms
[main] INFO spiffe.api.svid.util.ExponentialBackOff - Attempt no. 4
[main] INFO spiffe.api.svid.util.ExponentialBackOff - Error UNAVAILABLE: io exception
[main] INFO spiffe.api.svid.util.ExponentialBackOff - Sleeping for 16000ms
[main] INFO spiffe.api.svid.util.ExponentialBackOff - Attempt no. 5
[main] INFO ClientExample - Spiffe ID fetched: spiffe://example.org/workload

```

### Generating the JAR 

```
./gradlew build
```

The jar file `java-spiffe-0.1-SNAPSHOT.jar` is generated in folder `libs`.