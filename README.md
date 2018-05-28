# JAVA-SPIFFE library

## Overview

The JAVA-SPIFFE library provides functionality to fetch SVIDs Bundles from a Workload API

## SPIFFE Workload API Client

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
