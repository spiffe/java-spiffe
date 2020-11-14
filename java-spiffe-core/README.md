# JAVA-SPIFFE Core

Core functionality to fetch, process and validate X.509 and JWT SVIDs and Bundles from the Workload API.

It uses the [JWT and JOSE Nimbus Library](https://connect2id.com/products/nimbus-jose-jwt) to parse and process the JWT tokens 
and JSON Web Key (JWK) set bundles. 

## X.509 Source

A `X509Source` represents a source of X.509 SVIDs and X.509 bundles maintained via the Workload API.

To create a new X.509 Source:

```
    X509Source x509Source; 
    try {
        x509Source = DefaultX509Source.newSource();
    } catch (SocketEndpointAddressException | X509SourceException | BundleNotFoundException e) {
        // handle exception
    }

    X509Svid svid = x509Source.getX509Svid();
    X509Bundle bundle = x509Source.getBundleForTrustDomain(TrustDomain.of("example.org"));
```

The `newSource()` method blocks until the X.509 materials can be retrieved from the Workload API and the `X509Source` is 
initialized with the X.509 SVIDs and Bundles. A `X.509 context watcher` is configured on the `X509Source` to automatically get 
the updates from the Workload API. This watcher performs retries if at any time the connection to the Workload API 
reports an error.

The socket endpoint address is configured through the environment variable `SPIFFE_ENDPOINT_SOCKET`. Another way to
configure it is by providing an `X509SourceOptions` instance to the `newSource` method:

```
    X509Source.X509SourceOptions x509SourceOptions = X509Source.X509SourceOptions
            .builder()
            .spiffeSocketPath("unix:/tmp/agent-other.sock")
            .picker(list -> list.get(list.size()-1))
            .build();
    
    X509Source x509Source = DefaultX509Source.newSource(x509SourceOptions);
```

It allows to configure another SVID picker. By default, the first SVID is used. 

### Configure a timeout for X509Source initialization 

The `X509Source newSource()` method blocks waiting until an X.509 context is fetched. The X.509 context fetch is retried
using an exponential backoff policy with this progression of delays between retries: 1 second, 2 seconds, 4, 8, 16, 32, 60, 60, 60...
It retries indefinitely unless a timeout is configured. 

This timeout can be configured either providing it through the `newSource(Duration timeout)` method or 
using a System property:

`spiffe.newX509Source.timeout=PT30S`

The `timeout` duration is expressed in `ISO-8601` format.


## JWT Source

A `JwtSource` represents a source of JWT SVIDs and bundles maintained via the Workload API.

To create a new JWT Source:

```
    JwtSource jwtSource; 
    try {
        jwtSource = JwtSource.newSource();
    } catch (SocketEndpointAddressException | JwtSourceException e) {
        // handle exception
    }

    JwtSvid svid = jwtSource.fetchJwtSvid(SpiffeId.parse("spiffe://example.org/test"), "testaudience1", "audience2");

    JwtBundle bundle = jwtSource.getBundleForTrustDomain(TrustDomain.of("example.org"));
```

The `newSource()` method blocks until the JWT materials can be retrieved from the Workload API and the `JwtSource` is 
initialized with the JWT Bundles. A `JWT context watcher` is configured on the JwtSource to automatically get 
the updates from the Workload API. This watcher performs retries if at any time the connection to the Workload API 
reports an error.

The socket endpoint address is configured through the environment variable `SPIFFE_ENDPOINT_SOCKET`. 

Another way to configure it is by providing an `JwtSourceOptions` instance to the `newSource` method:

```
    JwtSource.JwtSourceOptions jwtSourceOptions = JwtSource.JwtSourceOptions
            .builder()
            .spiffeSocketPath("unix:/tmp/agent-other.sock")
            .build();
    
    JwtSource jwtSource = JwtSource.newSource(jwtSourceOptions);
```

### Configure a timeout for JwtSource initialization 

The `JwtSource newSource()` method blocks until the JWT materials are fetched. The fetching process is retried
using an exponential backoff policy with this progression of delays between retries: 1 second, 2 seconds, 4, 8, 16, 32, 60, 60, 60...
It retries indefinitely unless a timeout is configured. 

This timeout can be configured either providing it through the `newSource(Duration timeout)` method or 
using a System property:

`spiffe.newJwtSource.timeout=PT30S`

The `timeout` duration is expressed in `ISO-8601` format.

