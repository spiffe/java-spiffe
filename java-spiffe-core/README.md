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
    } catch (SocketEndpointAddressException | X509SourceException e) {
        // handle exception
    }

    X509Svid svid = x509Source.getX509Svid();
    X509Bundle bundle = x509Source.getBundleForTrustDomain(TrustDomain.parse("example.org"));
```

The `newSource()` method blocks until the X.509 materials can be retrieved from the Workload API and the `X509Source` is 
initialized with the X.509 SVIDs and Bundles. A `X.509 context watcher` is configured on the `X509Source` to automatically get 
the updates from the Workload API. This watcher performs retries if at any time the connection to the Workload API 
reports an error.

The socket endpoint address is configured through the environment variable `SPIFFE_ENDPOINT_SOCKET`. Another way to
configure it is by providing an `X509SourceOptions` instance to the `newSource` method:

```
    DefaultX509Source.X509SourceOptions x509SourceOptions = DefaultX509Source.X509SourceOptions
            .builder()
            .spiffeSocketPath("unix:/tmp/agent-other.sock")
            .svidPicker(list -> list.get(list.size()-1))
            .build();
    
    X509Source x509Source = DefaultX509Source.newSource(x509SourceOptions);
```

It allows to configure another SVID picker. By default, the first SVID is used. 

### Configure a timeout for X509Source initialization 

The `X509Source newSource()` method blocks waiting until an X.509 context is fetched. The X.509 context fetch is retried
using an exponential backoff policy with this progression of delays between retries: 1 second, 2 seconds, 4, 8, 16, 32, 60, 60, 60...
It retries indefinitely unless a timeout is configured. This includes `PERMISSION_DENIED`, so an unregistered
workload waits for registration instead of failing immediately. Set a nonzero `initTimeout` to bound this wait.

This timeout can be configured either with the `initTimeout` option of the `X509SourceOptions` passed to the
`newSource(X509SourceOptions options)` method:

```
    DefaultX509Source.X509SourceOptions x509SourceOptions = DefaultX509Source.X509SourceOptions
            .builder()
            .initTimeout(Duration.ofSeconds(30))
            .build();

    X509Source x509Source = DefaultX509Source.newSource(x509SourceOptions);
```

or with a System property, which is used when the options don't set an `initTimeout`:

`-Dspiffe.newX509Source.timeout=PT30S`

The System property is expressed in `ISO-8601` format. It is read once, when the `DefaultX509Source` class is
loaded, so it has to be set before then, for example on the `java` command line.

If the X.509 context cannot be fetched before the timeout expires, `newSource` throws an `X509SourceException`.


## JWT Source

A `JwtSource` represents a source of JWT SVIDs and bundles maintained via the Workload API.

To create a new JWT Source:

```
    JwtSource jwtSource; 
    try {
        jwtSource = DefaultJwtSource.newSource();
    } catch (SocketEndpointAddressException | JwtSourceException e) {
        // handle exception
    }

    JwtSvid svid = jwtSource.fetchJwtSvid(SpiffeId.parse("spiffe://example.org/test"), "testaudience1", "audience2");

    JwtBundle bundle = jwtSource.getBundleForTrustDomain(TrustDomain.parse("example.org"));
```

The `newSource()` method blocks until the JWT materials can be retrieved from the Workload API and the `JwtSource` is 
initialized with the JWT Bundles. A `JWT context watcher` is configured on the JwtSource to automatically get 
the updates from the Workload API. This watcher performs retries if at any time the connection to the Workload API 
reports an error.

The socket endpoint address is configured through the environment variable `SPIFFE_ENDPOINT_SOCKET`. 

Another way to configure it is by providing an `JwtSourceOptions` instance to the `newSource` method:

```
    JwtSourceOptions jwtSourceOptions = JwtSourceOptions
            .builder()
            .spiffeSocketPath("unix:/tmp/agent-other.sock")
            .build();
    
    JwtSource jwtSource = DefaultJwtSource.newSource(jwtSourceOptions);
```

### Cache JWT-SVIDs

`DefaultJwtSource` fetches a new JWT-SVID from the Workload API on every `fetchJwtSvid` and `fetchJwtSvids` call.
To reuse JWT-SVIDs, create the source with `CachedJwtSource` instead, which has the same `newSource` methods and
options:

```
    JwtSource jwtSource = CachedJwtSource.newSource();
```

It caches the JWT-SVIDs per subject SPIFFE ID and set of audiences, and fetches new ones from the Workload API once
the cached JWT-SVIDs have passed half of their lifetime.

### Configure a timeout for JwtSource initialization 

The `JwtSource newSource()` method blocks until the JWT materials are fetched. The fetching process is retried
using an exponential backoff policy with this progression of delays between retries: 1 second, 2 seconds, 4, 8, 16, 32, 60, 60, 60...
It retries indefinitely unless a timeout is configured. This includes `PERMISSION_DENIED`, so an unregistered
workload waits for registration instead of failing immediately. Set a nonzero `initTimeout` to bound this wait.

This timeout can be configured either with the `initTimeout` option of the `JwtSourceOptions` passed to the
`newSource(JwtSourceOptions options)` method:

```
    JwtSourceOptions jwtSourceOptions = JwtSourceOptions
            .builder()
            .initTimeout(Duration.ofSeconds(30))
            .build();

    JwtSource jwtSource = DefaultJwtSource.newSource(jwtSourceOptions);
```

or with a System property, which is used when the options don't set an `initTimeout`:

`-Dspiffe.newJwtSource.timeout=PT30S`

The System property is expressed in `ISO-8601` format. It is read once, when the `DefaultJwtSource` or
`CachedJwtSource` class is loaded, so it has to be set before then, for example on the `java` command line.

If the JWT bundles cannot be fetched before the timeout expires, `newSource` throws a `JwtSourceException`.

## Validate JWT-SVIDs

A `JwtSource` is also a source of JWT bundles, so it can be used to validate the JWT-SVIDs received from other
workloads. `JwtSvid.parseAndValidate` verifies the token signature with the JWT authorities of the trust domain of
the token's subject, and checks that the token has not expired and that its `aud` claim contains all the expected
audiences:

```
    JwtSvid svid = JwtSvid.parseAndValidate(token, jwtSource, Collections.singleton("audience1"));
    SpiffeId peerSpiffeId = svid.getSpiffeId();
```

It throws a `JwtSvidException` if the token is not a valid JWT-SVID, has expired, has an invalid signature or its
`aud` claim does not contain the expected audiences, an `IllegalArgumentException` if the token is blank or cannot be
parsed (or if the audience set is empty), a `BundleNotFoundException` if there is no JWT bundle for the
trust domain of the subject, and an `AuthorityNotFoundException` if the bundle has no JWT authority with the key ID
of the token. `JwtSvid.parseInsecure` parses and checks a token like `parseAndValidate`, but without verifying its
signature.

## Marshal X.509-SVIDs

An `X509Svid` can be marshaled into PEM-encoded certificates and a PEM-encoded PKCS#8 private key, the formats that
`X509Svid.load` and `X509Svid.parse` read. This lets a workload hand its SVID to a process or tool that takes
certificate and key files:

```
    X509Svid svid = x509Source.getX509Svid();
    Files.write(Paths.get("/tmp/svid.pem"), svid.marshalCertificates());
    Path keyPath = Files.createFile(Paths.get("/tmp/svid.key"),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
    Files.write(keyPath, svid.marshalPrivateKey());
    X509Svid loadedSvid = X509Svid.load(Paths.get("/tmp/svid.pem"), keyPath);
```

The certificate chain is written leaf first. The private key is not encrypted, so store it where only the workload
can read it. The SVID hint is not marshaled; pass it to `X509Svid.parse` to keep it. `marshalRawCertificates` and `marshalRawPrivateKey` return the same material as ASN.1 DER, which
`X509Svid.parseRaw` reads.

## Marshal bundles

An `X509Bundle` can be marshaled into PEM-encoded certificates, and a `JwtBundle` into a standard RFC 7517 JWKS
document. These are the formats that `X509Bundle.parse` and `JwtBundle.parse` read, so a bundle obtained from a
source can be stored or shared and loaded back later:

```
    X509Bundle x509Bundle = x509Source.getBundleForTrustDomain(TrustDomain.parse("example.org"));
    Files.write(Paths.get("/tmp/bundle.pem"), x509Bundle.marshal());
    X509Bundle loadedX509Bundle = X509Bundle.load(TrustDomain.parse("example.org"), Paths.get("/tmp/bundle.pem"));

    JwtBundle jwtBundle = jwtSource.getBundleForTrustDomain(TrustDomain.parse("example.org"));
    Files.write(Paths.get("/tmp/bundle.jwks"), jwtBundle.marshal());
    JwtBundle loadedJwtBundle = JwtBundle.load(TrustDomain.parse("example.org"), Paths.get("/tmp/bundle.jwks"));
```

The bundles contain public material only. EC and RSA JWT authorities are supported.
