# JAVA-SPIFFE Core

Core functionality to fetch X509 and JWT SVIDs from the Workload API.

## X509Source

A `spiffe.workloadapi.X509Source` represents a source of X.509 SVIDs and X.509 bundles maintained via the Workload API.

To create a new X509 Source:

```
    try {
        x509Source = X509Source.newSource();
    } catch (SocketEndpointAddressException | X509SourceException e) {
        // handle exception
    }
```

The `newSource()` blocks until the X505 materials can be retrieved from the Workload API and the X509Source is 
initialized with the SVID and Bundles. A `X509 context watcher` is configured on the X509Source to get automatically
the updates from the Workload API. This watcher performs retries if at any time the connection to the Workload API 
reports an error.

The socket endpoint address is configured through the environment variable `SPIFFE_ENDPOINT_SOCKET`. Another way to
configure it is by providing a `X509SourceOptions` instance to the `newSource` method.

### Configure a timeout for X509Source initialization 

The method `X509Source newSource()` blocks waiting until a X509 context is fetched. The X509 context fetch is retried
using an exponential backoff policy with this progression of delays between retries: 1 second, 2 seconds, 4, 8, 16, 32, 60, 60, 60...
It retries indefinitely unless a timeout is configured. 

This timeout can be configured either providing it through the `newSource(Duration timeout)` method or 
using a System property:

`spiffe.newX509Source.timeout=30`

The Time Unit is seconds.

## Netty Event Loop thread number configuration

Use the variable `io.netty.eventLoopThreads` to configure the number of threads for the Netty Event Loop Group. 

By default, it is `availableProcessors * 2`.
