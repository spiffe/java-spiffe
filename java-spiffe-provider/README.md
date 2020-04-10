# JAVA-SPIFFE Provider

Java Security Provider implementation supporting X509-SVIDs.

## Add provider to Java Security

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


## Use Cases

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


### Create a SSL Context backed by the Workload API

TBD

## References 

[How to Implement a Provider in the Java Cryptography Architecture](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/HowToImplAProvider.html)

[Java PKI Programmer's Guide](https://docs.oracle.com/javase/8/docs/technotes/guides/security/certpath/CertPathProgGuide.html)
