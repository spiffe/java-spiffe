# Java SPIFFE Provider

This module provides a Java Security Provider implementation supporting X.509-SVIDs and methods for
creating `SSLContext` that are backed by the Workload API.

## Create an SSL Context backed by the Workload API

To create an `javax.net.ssl.SSLContext` that is backed by the Workload API through a `X509Source`, having the environment variable
` SPIFFE_ENDPOINT_SOCKET` defined with the Workload API endpoint address:

```
    X509Source source = DefaultX509Source.newSource();
    Supplier<Set<SpiffeId>> acceptedSpiffeIds = () -> Collections.singleton(SpiffeId.parse("spiffe://example.org/test"));
    SslContextOptions options = SslContextOptions
            .builder()
            .x509Source(source)
            .acceptedSpiffeIdsSupplier(acceptedSpiffeIds)
            .build();

    SSLContext sslContext = SpiffeSslContextFactory.getSslContext(options);
```

The `SSLContext` is configured with a set of SPIFFE IDs that will be trusted for TLS connections.

    
Alternatively, a different Workload API address can be used by passing it to the `X509Source` creation method.

```
    X509SourceOptions sourceOptions = X509SourceOptions
            .builder()
            .spiffeSocketPath("unix:/tmp/agent.sock")
            .build();

    X509Source x509Source = DefaultX509Source.newSource(sourceOptions);
    Supplier<Set<SpiffeId>> acceptedSpiffeIds = () -> Collections.singleton(SpiffeId.parse("spiffe://example.org/test"));

    SslContextOptions sslContextOptions = SslContextOptions
            .builder()
            .acceptedSpiffeIdsSupplier(acceptedSpiffeIds)
            .x509Source(x509Source)
            .build();

    SSLContext sslContext = SpiffeSslContextFactory.getSslContext(sslContextOptions);
```

See [HttpsClient example](src/test/java/io/spiffe/provider/examples/mtls/HttpsClient.java) that defines a Supplier for providing
the list of SPIFFE IDs from a file.

## Plug Java SPIFFE Provider into Java Security architecture

Java Security Providers are configured in the master security properties file `<java-home>/jre/lib/security/java.security`. 

The way to register a java security provider is by specifying the custom `Provider` subclass name and the priority in the 
following format:

```
security.provider.<n>=<className>
```

This declares a provider, and specifies its preference order `n`.

#### Java 8
For installing the JAR file containing the provider classes as a bundled extension in the java platform, 
copy `build/libs/java-spiffe-provider-<version>-all-linux-x86_64.jar` to `<java-home>/jre/lib/ext`.

In the case of testing the provider in Mac OS, the name of the jar will be `java-spiffe-provider-<version>-all-osx-x86_64.jar`.

#### Java 9+ 

The `java-spiffe-provider` jar should be on the classpath.

### Extend `java.security` properties file

The master security properties file can be extended. Create a file `java.security` with the following content:
```
# Add the spiffe provider, change the <n> for the correct consecutive number
security.provider.<n>=io.spiffe.provider.SpiffeProvider

# Configure the default KeyManager and TrustManager factory algorithms 
ssl.KeyManagerFactory.algorithm=Spiffe
ssl.TrustManagerFactory.algorithm=Spiffe

# The list of spiffeIDs that will be authorized, separated by a pipe character
ssl.spiffe.accept=spiffe://example.org/workload | spiffe://example.org/workload2 | spiffe://example2.org/workload
```

In this `java.security` file: 

* replace `<n>` following the order of the `# List of Providers` in the master file. 

* replace the value of the custom property `ssl.spiffe.accept` with the SPIFFE IDs of the workloads that are 
allowed to connect, separated by the pipe character.
***If the property is not present or if it's empty, no SPIFFE ID will be authorized.*** 

To pass your custom security properties file through the command line via system property when starting the JVM:

```
-Djava.security.properties=<path to java.security>
```

The properties defined in your custom properties file will override the properties in the master file. 

The property `ssl.spiffe.accept` can also be defined through a System property passed as `-Dssl.spiffe.accept=`;

#### Accept all SPIFFE IDs

By default, only the SPIFFE IDs defined in the property `ssl.spiffe.accept` are accepted for a TLS connection. Thus,
if the property is empty or not defined, no SPIFFE ID will be accepted. To accept all SPIFFE IDs it should be used
the property `ssl.spiffe.acceptAll` and set as `true` in the Security properties file:

```
ssl.spiffe.acceptAll=true
```

or through a System property: `-Dssl.spiffe.acceptAll=true`.

It can also be configured when the SSL Context is created programmatically setting as `true` the option `acceptAnySpiffeId` 
in the `SslContextOptions`:

```
SslContextOptions sslContextOptions = SslContextOptions
            .builder()
            .x509Source(x509Source)
            .acceptAnySpiffeId()
            .build();

SSLContext sslContext = SpiffeSslContextFactory.getSslContext(sslContextOptions);
```

#### Configure Workload API Socket Endpoint

The socket endpoint can be configured defining an environment variable named `SPIFFE_ENDPOINT_SOCKET`: 

```
export SPIFFE_ENDPOINT_SOCKET=/tmp/agent.sock
``` 

## Use Cases

### Connect to Postgres DB using TLS and the SPIFFE SslSocketFactory 

A Java app can connect to a Postgres DB using TLS and authenticate itself using certificates provided by SPIRE through
the SPIFFE Workload API. To enable this functionality, there's a custom `SSLSocketFactory` implementation that injects a 
custom `SSLContext` that uses the SPIFFE `KeyStore` and a `TrustStore` implementations to obtain certificates and bundles
from a SPIRE Agent, keep them updated in memory, and provide them for TLS connections.

The URL to connect to Postgres using TLS and Java SPIFFE is as follows:

```
jdbc:postgresql://localhost:5432/postgres?sslmode=require&sslfactory=io.spiffe.provider.SpiffeSslSocketFactory
```

The parameter `sslfactory` in the URL configures the Postgres JDBC driver to use the `SpiffeSslSocketFactory` which wraps 
around an SSL Socket with the Java SPIFFE functionality.

The Workload API socket endpoint should be configured through the Environment variable `SPIFFE_ENDPOINT_SOCKET`.

During the connection to a Postgres DB, the server presents its certificate, which is validated using trust bundles
obtained from the SPIFFE Workload API. 
To also validate that the SPIFFE ID presented in the server's certificate is one of a list of expected SPIFFE IDs, 
the property `ssl.spiffe.accept` needs to be configured with the expected SPIFFE IDs separated by commas.  
For example:

```
-Dssl.spiffe.accept=spiffe://domain.test/db-1,spiffe://domain.test/db-2'
```
If this property is not configured, any SPIFFE ID will be accepted in a TLS connection.

### Configure a Tomcat connector

***Prerequisite***: Having the SPIFFE Provider configured through the `java.security`.

A Tomcat TLS connector that uses the `Spiffe` KeyStore can be configured as follows: 

```
<Connector
            protocol="org.apache.coyote.http11.Http11NioProtocol"
            port="8443" maxThreads="200"
            scheme="https" secure="true" SSLEnabled="true"
            keystoreFile="" keystorePass=""
            keystoreType="Spiffe"
            clientAuth="true" sslProtocol="TLS"/>
```

### Create mTLS GRPC server and client

Prerequisite: Having the SPIFFE Provider configured through the `java.security`.

A `GRPC Server` using an SSL context backed by the Workload API:

```
    KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(SpiffeProviderConstants.ALGORITHM);
    TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(SpiffeProviderConstants.ALGORITHM);

    SslContextBuilder sslContextBuilder =
            SslContextBuilder
                    .forServer(keyManagerFactory)
                    .trustManager(trustManagerFactory);

    Server server = NettyServerBuilder.forPort(9000)
            .sslContext(GrpcSslContexts.configure(sslContextBuilder)
                    .clientAuth(ClientAuth.REQUIRE)
                    .build())
            .build();

    server.start();
```

#### Configure it programmatically:

The `SpiffeKeyManager` and `SpiffeTrustManager` can be created without resorting to factories, providing the constructors
with a [X509Source instance](../java-spiffe-core/README.md#x509-source).

```
    // create a new X.509 source using the default socket endpoint address
    X509Source x509Source = DefaultX509Source.newSource();

    // KeyManager gets the X.509 cert and private key from the X.509 SVID source
    KeyManager keyManager = new SpiffeKeyManager(x509Source);

    // TrustManager gets the X509Source and the supplier of the Set of accepted SPIFFE IDs.
    TrustManager trustManager = new SpiffeTrustManager(x509Source, () -> SpiffeIdUtils.toSetOfSpiffeIds("spiffe://example.org/workload-client"));

    SslContextBuilder sslContextBuilder =
            SslContextBuilder
            .forServer(keyManager)
            .trustManager(trustManager);

    Server server = NettyServerBuilder.forPort(9000)
            .addService(new GreetingServiceImpl())
            .sslContext(GrpcSslContexts.configure(sslContextBuilder)
                    .clientAuth(ClientAuth.REQUIRE)
                    .build())
            .build();
``` 

For the client, a `ManagedChannel` would be created using the `SpiffeKeyManager` and `SpiffeTrustManager` for configuring 
the GRPC SSL context, analogous to the config for the Server:

``` 
    X509Source x509Source = DefaultX509Source.newSource();

    KeyManager keyManager = new SpiffeKeyManager(x509Source);

    Supplier<Set<SpiffeId>> acceptedSpiffeIds = () -> SpiffeIdUtils.toSetOfSpiffeIds("spiffe://example.org/workload-server");
    TrustManager trustManager = new SpiffeTrustManager(x509Source, acceptedSpiffeIds);

    SslContextBuilder sslContextBuilder = SslContextBuilder
            .forClient()
            .trustManager(trustManager)
            .keyManager(keyManager)
            .clientAuth(ClientAuth.REQUIRE);
    
    ManagedChannel channel = NettyChannelBuilder.forAddress("localhost", 9000)
            .sslContext(GrpcSslContexts.configure(sslContextBuilder).build())
            .build();
```

### Secure Socket Example:
See [HttpsServer example](src/test/java/io/spiffe/provider/examples/mtls/HttpsServer.java).

## More information 

[Java Platform Security Developer’s Guide](https://docs.oracle.com/en/java/javase/14/security/)

[How to Implement a Provider in the Java Cryptography Architecture](https://docs.oracle.com/en/java/javase/14/security/howtoimplaprovider.html)

[Java PKI Programmer's Guide](https://docs.oracle.com/en/java/javase/14/security/java-pki-programmers-guide.html)
