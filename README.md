# JAVA-SPIFFE library

## Overview

The JAVA-SPIFFE library provides two components: 
 
 - a Client that implements the functionality to fetch SVIDs Bundles from a Workload API. 

 - an SVID based KeyStore and TrustStore implementation that handles the certificates in memory
and receives the updates asynchronously from the Workload API. Using the terminology of the Java Security API, 
this library provides a custom Security Provider that can be installed in the JVM. 

It supports Federation. The TrustStore validates the peer's SVID using a set of Trusted CAs that includes the 
Federated TrustDomains CAs bundles. These Federates CAs bundles come from the Workload API in the X509SVIDResponse.

## SPIFFE Workload API Client Example

The `X509SVIDFetcher` provides the `registerListener` method that allows a consumer to register a listener 
to get the X509-SVIDS whenever the Workload API has a new SVID to push. 

The gRPC channel is configured based on the Address (tcp or unix socket) and the OS detected.

### Use

```
Fetcher<X509SVIDResponse> svidFetcher = new X509SVIDFetcher("/tmp/agent.sock");

Consumer<X509SVIDResponse> xvidConsumer = x509SVIDResponse -> {
            x509SVIDResponse.getSvidsList().forEach(svid -> {
                System.out.println("Spiffe ID fetched: " + svid.getSpiffeId());
                System.out.println("Federated with: " + svid.getFederatesWithList());
            });
            System.out.println(x509SVIDResponse.getFederatedBundlesMap());
        };

//Registering the callback to receive the SVIDs from the Workload API
svidFetcher.registerListener(xvidConsumer);
```

The `X509SVIDFetcher` can be configured with a custom `RetryPolicy`. 

By default it uses a `RetryPolicy` with the following parameters:

```
initialDelay = 1;
maxDelay = 300;
timeUnit = SECONDS;
expBackoffBase = 2
maxRetries = UNLIMITED_RETRIES;
```

## SPIFFE SVID based KeyStore and TrustStore Provider

### Install the SPIFFE Provider JAR

Generate the JAR: 

```
./gradlew build
```

For installing the JAR file containing the provider classes as a bundled extension in the java platform, copy 
`build/libs/spiffe-provider-0.1.0.jar` to `<java-home>/jre/lib/ext`

### Configure `java.security` 

Java Security Providers are configured in the master security properties file `<java-home>/lib/security/java.security`. 

The way to register a provider is to specify the Provider subclass name and priority in the format

```
security.provider.<n>=<className>
```

This declares a provider, and specifies its preference order n.

#### Register the SPIFFE Provider

You can extend and override the master security properties file. 

Create a file `java.security` with the following content:

```
security.provider.<n>=spiffe.provider.SpiffeProvider

# Determines the default key and trust manager factory algorithms for
# the javax.net.ssl package.
ssl.KeyManagerFactory.algorithm=Spiffe
ssl.TrustManagerFactory.algorithm=Spiffe

# The list of spiffeIDs that will be authorized
ssl.spiffe.accept=spiffe://example.org/workload, spiffe://example.org/workload2, spiffe://example2.org/workload
```

In your `java.security` file: 

* replace `<n>` following the order of the `# List of Providers` in the master file. 

* replace the value of the custom property `ssl.spiffe.accept` with the Spiffe IDs of the workloads that are allowed to connect.

To pass your custom security properties file through the command line via system property when starting the JVM:

```
-Djava.security.properties=<path to java.security>
```

For example, it can be passed in the `JAVA_OPTS` used by the Tomcat's startup script: 

```
$ export JAVA_OPTS="$JAVA_OPTS -Djava.security.properties=java.security"
$ ./catalina.sh run
```

The properties defined in your custom properties file will override the properties in the master file. 

### Configure Workload API Socket Endpoint

The socket endpoint can be configured defining an environment variable named `SPIFFE_ENDPOINT_SOCKET`: 

```
export SPIFFE_ENDPOINT_SOCKET=/tmp/agent.sock
``` 

or it can be configured from the command line via system property: 

```
-Dspiffe.endpoint.socket=/tmp/agent.sock
```

If both are defined, system property overrules. 

If the endpoint socket is not defined, there will be an error stating `SPIFFE_ENDPOINT_SOCKET is not defined`.

### Configure a Tomcat connector

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

## Running Demo

A running example using the SPIFFE Provider in Tomcat is available in [java-spiffe-example](https://github.com/spiffe/spiffe-example/tree/master/java-keystore-tomcat-demo)

## References 

[How to Implement a Provider in the Java Cryptography Architecture](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/HowToImplAProvider.html)

[Java PKI Programmer's Guide](https://docs.oracle.com/javase/8/docs/technotes/guides/security/certpath/CertPathProgGuide.html)
