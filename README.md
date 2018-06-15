# JAVA-SPIFFE library

## Overview

The JAVA-SPIFFE library provides functionality to fetch SVIDs Bundles from a Workload API

## SPIFFE Workload API ClientExample

The `X509SvidFetcher` provides the method `registerListener` that allows a consumer to register a listener 
to get the X509-SVIDS whenever the Workload API something new to send. 

The channel is configured based on the Address (tcp or unix socket) and the OS detected.

## Use
```
Fetcher<List<X509SVID>> svidFetcher = new X509SvidFetcher("/tmp/agent.sock");
Consumer<List<X509SVID>> certificateUpdater;
certificateUpdater = certs -> {
    certs.forEach(svid -> {
        System.out.println("Spiffe ID fetched: " + svid.getSpiffeId());
    });
};

//Calling the WorkloadAPI to obtain the certificates
svidFetcher.registerListener(certificateUpdater);
```

The `X509SvidFetcher` can be configured with a custom `RetryPolicy`. 

By default it uses a `RetryPolicy` with the following parameters:

```
initialDelay = 1;
maxDelay = 300;
timeUnit = SECONDS;
expBackoffBase = 2
maxRetries = UNLIMITED_RETRIES;
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

To start the Java server you can run `./gradlew runExample`

```
$ ./gradlew runExample

> Task :run
[main] INFO spiffe.api.svid.examples.ClientExample - Fetching the SVIDs asynchronously
[main] INFO spiffe.api.svid.examples.ClientExample - Waiting for certificates...
[main] INFO spiffe.api.svid.examples.ClientExample - Doing other work...
[main] INFO spiffe.api.svid.examples.ClientExample - Doing other work...
[main] INFO spiffe.api.svid.examples.ClientExample - Doing other work...
[grpc-default-executor-0] INFO spiffe.api.svid.examples.ClientExample - Spiffe ID fetched: spiffe://example.org/workload
[main] INFO spiffe.api.svid.examples.ClientExample - Exiting...

BUILD SUCCESSFUL in 1s

```

### Generating the JAR  

```
./gradlew build
```

The jar file `java-spiffe-0.1-SNAPSHOT.jar` is generated in folder `libs`.

### Generating the fat JAR with all the dependencies

```
./gradlew shadowJar
```

The jar file `java-spiffe-0.1-SNAPSHOT-all.jar` is generated in folder `libs`.
