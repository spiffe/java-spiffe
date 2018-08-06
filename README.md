# JAVA-SPIFFE library

## Overview

The JAVA-SPIFFE library provides two components: 
 
 - a Client that implements the functionality to fetch SVIDs Bundles from a Workload API. 

 - a SVID based KeyStore and TrustStore implementation that handles the certificates in memory
and receives the updates asynchronously from the Workload API. Using the terminology of the Java Security API, 
this library provides a custom Security Provider that can be installed in the JVM. 

## SPIFFE Workload API Client Example

The `X509SVIDFetcher` provides the method `registerListener` that allows a consumer to register a listener 
to get the X509-SVIDS whenever the Workload API has a new SVID to push. 

The gRPC channel is configured based on the Address (tcp or unix socket) and the OS detected.

### Use

```
Fetcher<List<X509SVID>> svidFetcher = new X509SVIDFetcher("/tmp/agent.sock");
Consumer<List<X509SVID>> certificateUpdater;
certificateUpdater = certs -> {
    certs.forEach(svid -> {
        System.out.println("Spiffe ID fetched: " + svid.getSpiffeId());
    });
};

//Registering the callback to receive the SVIDs from the Workload API
svidFetcher.registerListener(certificateUpdater);
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

Java Security Providers are configured in the the master security properties file `<java-home>/lib/security/java.security`. 
You can extend and override that file. 

Create a file `java.security` with the following content: 

```
# Adding provider following the numeration of the List of Providers in the master file
security.provider.10=spiffe.provider.SpiffeProvider

# Determines the default key and trust manager factory algorithms for
# the javax.net.ssl package.
ssl.KeyManagerFactory.algorithm=Spiffe
ssl.TrustManagerFactory.algorithm=Spiffe

# The spiffeID that will be trusted
ssl.spiffe.accept=spiffe://example.org/front-end
```

Replace the value of `ssl.spiffe.accept` with the Spiffe ID of the workload that is allowed to connect to your workload.

Pass your custom security properties through the command line via system property: 

```
-Djava.security.properties=<path to java.security>
```

The properties defined in your custom properties file will override the properties in the master file. 

### Configure Workload API Socket Endpoint

The socket endpoint can be configured defining a environment variable named `SPIFFE_ENDPOINT_SOCKET`: 

```
export SPIFFE_ENDPOINT_SOCKET=/tmp/agent.sock
``` 

or it can be configured from the command line via system property: 

```
-Dspiffe.endpoint.socket=/tmp/agent.sock
```

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

A running example using the SPIFFE Provider in Tomcat is available in [java-spiffe-example](https://github.com/spiffe/spiffe-example/tree/master/spiffe-keystore-tomcat)

## References 

[How to Implement a Provider in the Java Cryptography Architecture](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/HowToImplAProvider.html)

[Java PKI Programmer's Guide](https://docs.oracle.com/javase/8/docs/technotes/guides/security/certpath/CertPathProgGuide.html)
