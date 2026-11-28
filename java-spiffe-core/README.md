# JAVA-SPIFFE Core

Core functionality to fetch, process and validate X.509 and JWT SVIDs and Bundles from the Workload API.

For changes affecting existing callers, see [Upgrading to 0.9.0](../CHANGELOG.md#upgrade-considerations).

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

The `newSource()` method waits for the initial X.509 SVIDs and bundles, or fails on an initialization error or a
configured timeout. An X.509 context watcher maintains subsequent updates.
Under the default client policy, retryable errors reconnect with backoff; terminal statuses such as
`FAILED_PRECONDITION` end the watch. See the [watch retry changes](../CHANGELOG.md#breaking-changes)
and [source recovery instructions](../CHANGELOG.md#upgrade-considerations).

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

The `newSource()` method waits for the initial X.509 context. A zero initialization timeout means there is no
deadline; it does not make terminal errors retryable. Under the default policy, retryable errors use exponential
backoff with delays of 1, 2, 4, 8, 16, 32, then 60 seconds between attempts. An initial `PERMISSION_DENIED` can retry
indefinitely while an unregistered workload waits for registration. A terminal status such as `FAILED_PRECONDITION`
can fail initialization immediately with `X509SourceException`, even with a zero timeout. Set a nonzero `initTimeout`
to bound the wait for retryable failures.

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

The `newSource()` method waits for the initial JWT bundles, or fails on an initialization error or a configured
timeout. A JWT bundle watcher maintains subsequent updates.
Under the default client policy, retryable errors reconnect with backoff; terminal statuses such as
`FAILED_PRECONDITION` end the watch. The same initialization and watch behavior applies to `CachedJwtSource`.
See the [watch retry changes](../CHANGELOG.md#breaking-changes)
and [source recovery instructions](../CHANGELOG.md#upgrade-considerations).

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

`DefaultJwtSource.newSource()` and `CachedJwtSource.newSource()` wait for the initial JWT bundles. A zero
initialization timeout means there is no deadline; it does not make terminal errors retryable. Under the default
policy, retryable errors use exponential backoff with delays of 1, 2, 4, 8, 16, 32, then 60 seconds between attempts.
An initial `PERMISSION_DENIED` can retry indefinitely while an unregistered workload waits for registration.
A terminal status such as `FAILED_PRECONDITION` can fail initialization immediately with `JwtSourceException`,
even with a zero timeout. Set a nonzero `initTimeout` to bound the wait for retryable failures.

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

## SPIFFE IDs

A `SpiffeId` can be parsed from a string, or built from a trust domain and either a path or path segments. The path
and the segments are validated according to the [SPIFFE ID specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#22-path),
and an `InvalidSpiffeIdException` is thrown if they are not valid:

```
    TrustDomain trustDomain = TrustDomain.parse("example.org");

    SpiffeId backend = SpiffeId.parse("spiffe://example.org/backend");
    SpiffeId sameBackend = SpiffeId.fromPath(trustDomain, "/backend");
    SpiffeId alsoBackend = SpiffeId.fromSegments(trustDomain, "backend");
```

A `SpiffeId` is immutable. `appendPath` and `appendSegments` return a new SPIFFE ID with the path extended, and
`replacePath` and `replaceSegments` return a new SPIFFE ID in the same trust domain with a different path:

```
    SpiffeId api = backend.appendPath("/api/v1");               // spiffe://example.org/backend/api/v1
    SpiffeId sameApi = backend.appendSegments("api", "v1");     // spiffe://example.org/backend/api/v1
    SpiffeId frontend = api.replacePath("/frontend");           // spiffe://example.org/frontend
    SpiffeId sameFrontend = api.replaceSegments("frontend");    // spiffe://example.org/frontend
```

A path must start with `/` and cannot have a trailing slash, while path segments must not contain `/`. `fromPath` and
`replacePath` with an empty path, and `fromSegments` and `replaceSegments` with no segments, return the SPIFFE ID of
the trust domain itself, `spiffe://example.org`.
