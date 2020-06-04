# JAVA-SPIFFE Core

Core functionality to fetch, process and validate X.509 and JWT SVIDs and Bundles from the Workload API.

## X.509 Source

A `spiffe.workloadapi.X509Source` represents a source of X.509 SVIDs and X.509 bundles maintained via the Workload API.

To create a new X509 Source:

```
    X509Source x509Source; 
    try {
        x509Source = X509Source.newSource();
    } catch (SocketEndpointAddressException | X509SourceException e) {
        // handle exception
    }

    X509Svid svid = x509Source.getX509Svid();
    X509Bundle bundle = x509Source.getX509BundleForTrustDomain(TrustDomain.of("example.org"));
```

The `newSource()` blocks until the X.509 materials can be retrieved from the Workload API and the X509Source is 
initialized with the X.509 SVIDs and Bundles. A `X509 context watcher` is configured on the X509Source to get automatically
the updates from the Workload API. This watcher performs retries if at any time the connection to the Workload API 
reports an error.

The socket endpoint address is configured through the environment variable `SPIFFE_ENDPOINT_SOCKET`. Another way to
configure it is by providing a `X509SourceOptions` instance to the `newSource` method:

```
    X509Source.X509SourceOptions x509SourceOptions = X509Source.X509SourceOptions
            .builder()
            .spiffeSocketPath("unix:/tmp/agent-other.sock")
            .picker(list -> list.get(list.size()-1))
            .build();
    
    X509Source x509Source = X509Source.newSource(x509SourceOptions);
```

It allows to configure another SVID picker. By default, the first SVID is used. 

### Configure a timeout for X509Source initialization 

The method `X509Source newSource()` blocks waiting until a X509 context is fetched. The X509 context fetch is retried
using an exponential backoff policy with this progression of delays between retries: 1 second, 2 seconds, 4, 8, 16, 32, 60, 60, 60...
It retries indefinitely unless a timeout is configured. 

This timeout can be configured either providing it through the `newSource(Duration timeout)` method or 
using a System property:

`spiffe.newX509Source.timeout=30`

The Time Unit is seconds.


## JWT Source

A `spiffe.workloadapi.JwtSource` represents a source of JWT SVIDs and bundles maintained via the Workload API.

To create a new JWT Source:

```
    JwtSource jwtSource; 
    try {
        jwtSource = JwtSource.newSource();
    } catch (SocketEndpointAddressException | JwtSourceException e) {
        // handle exception
    }

    JwtSvid svid = jwtSource.fetchJwtSvid(SpiffeId.parse("spiffe://example.org/test"), "testaudience1", "audience2");

    JwtBundle bundle = jwtSource.getJwtBundleForTrustDomain(TrustDomain.of("example.org"));
```

The `newSource()` blocks until the JWT materials can be retrieved from the Workload API and the JwtSource is 
initialized with the JWT Bundles. A `JWT context watcher` is configured on the JwtSource to get automatically
the updates from the Workload API. This watcher performs retries if at any time the connection to the Workload API 
reports an error.

The socket endpoint address is configured through the environment variable `SPIFFE_ENDPOINT_SOCKET`. 

## Netty Event Loop thread number configuration

Use the variable `io.netty.eventLoopThreads` to configure the number of threads for the Netty Event Loop Group. 

By default, it is `availableProcessors * 2`.
