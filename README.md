# JAVA-SPIFFE library

## Overview

The JAVA-SPIFFE library provides two components: 
 
 - a Client that implements the functionality to fetch SVIDs Bundles from a Workload API. 

 - an SVID based KeyStore and TrustStore implementation that handles the certificates in memory
and receives the updates asynchronously from the Workload API. Using the terminology of the Java Security API, 
this library provides a custom Security Provider that can be installed in the JVM. 

It supports Federation. The TrustStore validates the peer's SVID using a set of Trusted CAs that includes the 
Federated TrustDomains CAs bundles. These Federated CAs bundles come from the Workload API in the X509SVIDResponse.

Besides, this library provides a SocketFactory implementation to support TCP connections.

## SPIFFE Workload API Client Example

The `X509SVIDFetcher` provides the `registerListener` method that allows a consumer to register a listener 
to get the X509-SVIDS whenever the Workload API has a new SVID to push. 

The gRPC channel is configured based on the Address (tcp or unix socket) and the OS detected.

### Build the JAR

To create a fat JAR file that includes all the dependencies: 

```
 $ ./gradlew build
 
 BUILD SUCCESSFUL in 2s
```

In folder `build/libs` there will be a file `spiffe-provider-<version>-all.jar`.  


To create a slim JAR file:

```
 $ ./gradle jar
 BUILD SUCCESSFUL in 1s
```

In folder `build/libs` there will be a file `spiffe-provider-<version>.jar`. 


### Use

The library provides a `SpiffeIdManager` that abstracts low level details related to the interaction with the WorkloadAPI and exposes
getter methods to obtain the SVID, Bundle and Key:

```
SpiffeIdManager spiffeIdManager = SpiffeIdManager.getInstance();

PrivateKey privateKey = spiffeIdManager.getPrivateKey();
X509Certificate svid = spiffeIdManager.getCertificate();
Set<X509Certificate> bundle = spiffeIdManager.TrustedCerts();    
```

The `SpiffeIdManager` gets the certificate updates automatically from the WorkloadAPI. 

It uses a `X509SVIDFetcher` that handles the interaction with the WorkloadAPI. 

The path to the Socket where the Workload API is listening needs to configured either by setting the system property `-Dspiffe.endpoint.socket` or
or an the environment variable `SPIFFE_ENDPOINT_SOCKET`.


Another way to use the library is by directly instantiating the `X509SVIDFetcher` and registering a callback (aka Consumer) 
that will be invoked whenever there is an update pushed by the Workload API: 

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

In this case the path to the Socket is passed through a parameter in the constructor. If the parameter is not provided, it will
use the system property, if it is defined, or the environment variable. If neither is defined, it will throw an Exception. 

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

Generate the JAR that includes all dependencies: 

```
./gradlew build
```

For installing the JAR file containing the provider classes as a bundled extension in the java platform, copy 
`build/libs/spiffe-provider-<version>-all.jar` to `<java-home>/jre/lib/ext`

### Configure `java.security` 

Java Security Providers are configured in the master security properties file `<java-home>/jre/lib/security/java.security`. 

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
If the property is not present or if it's empty, any spiffe id will be authorized. 

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

## Running Demos

A running example using the SPIFFE Provider in Tomcat is available on [java-spiffe-example](https://github.com/spiffe/spiffe-example/tree/master/java-keystore-tomcat-demo)

A demo that shows Federation and TCP support is available on [java-spiffe-federation-jboss](https://github.com/spiffe/spiffe-example/tree/master/java-spiffe-federation-jboss)

## References 

[How to Implement a Provider in the Java Cryptography Architecture](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/HowToImplAProvider.html)

[Java PKI Programmer's Guide](https://docs.oracle.com/javase/8/docs/technotes/guides/security/certpath/CertPathProgGuide.html)
