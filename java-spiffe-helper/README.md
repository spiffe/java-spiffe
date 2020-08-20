# JAVA-SPIFFE Helper

The JAVA-SPIFFE Helper is a simple utility for fetching X.509 SVID certificates from the SPIFFE Workload API, 
and storing the Private Key and the chain of certificates in a Java KeyStore in disk, and the trusted bundles (CAs)
in a separated TrustStore in disk.

The Helper automatically gets the SVID updates and stores them in the KeyStore and TrustStore.

## Usage

On Linux:

`java -jar java-spiffe-helper-0.6.1-linux-x86_64.jar -c helper.conf`

On Mac OS:

`java -jar java-spiffe-helper-0.6.1-osx-x86_64.jar -c helper.conf`

(The jar can be found in `build/libs`, after running the gradle build)

Either `-c` or `--config` should be used to pass the path to the config file.

## Config file

```
keyStorePath = /tmp/keystore.p12
keyStorePass = example123
keyPass = pass123

trustStorePath = /tmp/truststore.p12
trustStorePass = otherpass123

keyStoreType = pkcs12

keyAlias = spiffe

spiffeSocketPath = unix:/tmp/agent.sock
```

### Configuration Properties

 |Configuration     | Description                                                                    | Default value |
 |------------------|--------------------------------------------------------------------------------| ------------- |
 |`keyStorePath`    | Path to the Java KeyStore File for storing the Private Key and chain of certs  |     none      |
 |`keyStorePass`    | Password to protect the Java KeyStore File                                     |     none      |
 |`keyPass`         | Password to protect the Private Key entry in the KeyStore                      |     none      |
 |`trustStorePath`  | Path to the Java TrustStore File for storing the trusted bundles               |     none      |
 |`trustStorePass`  | Password to protect the Java TrustStore File                                   |     none      |
 |`keyStoreType`    | Java KeyStore Type. (`pkcs12` and `jks` are supported). Case insensitive.      |     pkcs12    |
 |`keyAlias`        | Alias for the Private Key entry                                                |     spiffe    |
 |`spiffeSocketPath`| Path the Workload API                                                          |     Read from the system variable: SPIFFE_ENDPOINT_SOCKET  |
  
KeyStore and TrustStore **must** be in separate files. If `keyStorePath` and `trustStorePath` points to the same file, an error
is shown
. 
If the store files do not exist, they are created. 

The default and **recommended KeyStore Type** is `PKCS12`. The same type is used for both KeyStore and TrustStore.

It is **strongly recommended** to set restrictive file permissions for KeyStore file, since it stores a private key: 

`chmod 600 keystore_file_name`

Make sure the process running the JAVA-SPIFFE Helper has _write_ permission on the KeyStores files. 

### Debug

To check that the certs are being stored in the KeyStore:

`keytool -list -v -keystore keystore.path -storepass example123`

The output should be a `Private Key Entry`:

```
Keystore type: PKCS12
Keystore provider: SUN

Your keystore contains 1 entry

Alias name: spiffe
Creation date: Jun 2, 2020
Entry type: PrivateKeyEntry

Owner: O=SPIFFE, C=US
Issuer: O=SPIFFE, C=US
...
```

In the case of the TrustStore, it should display a `trustedCertEntry`:

```
Keystore type: PKCS12
Keystore provider: SUN

Your keystore contains 1 entry

Alias name: example.org.0
Creation date: Jun 2, 2020
Entry type: trustedCertEntry

Owner: O=SPIFFE, C=US
Issuer: O=SPIFFE, C=US
...
```

The aliases for the trusted certs are generated using the Trust Domain of the SPIFFE ID in the SAN URI, and adding a 
correlative number suffix.