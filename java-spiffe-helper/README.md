# JAVA-SPIFFE Helper

The JAVA-SPIFFE Helper is a simple utility for fetching X.509 SVID certificates from the SPIFFE Workload API, 
and storing the Private Key and the chain of certificates in a Java KeyStore in disk, and the trusted bundles (CAs)
in a separated TrustStore in disk.

The Helper automatically gets the SVID updates and stores them in the KeyStore and TrustStore.

## Usage

On Linux:

`java -jar java-spiffe-helper-0.8.17-linux-x86_64.jar`

On Mac OS:

`java -jar java-spiffe-helper-0.8.17-osx-x86_64.jar`

You can run the utility with the `-c` or `--config` option to specify the path to the configuration file. By default, it
will look for a configuration file named `conf/java-spiffe-helper.properties` in the current working directory.

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

| Configuration      | Description                                                                   | Default value                                         |
 |--------------------|-------------------------------------------------------------------------------|-------------------------------------------------------|
| `keyStorePath`     | Path to the Java KeyStore File for storing the Private Key and chain of certs | none                                                  |
| `keyStorePass`     | Password to protect the Java KeyStore File                                    | none                                                  |
| `keyPass`          | Password to protect the Private Key entry in the KeyStore                     | none                                                  |
| `trustStorePath`   | Path to the Java TrustStore File for storing the trusted bundles              | none                                                  |
| `trustStorePass`   | Password to protect the Java TrustStore File                                  | none                                                  |
| `keyStoreType`     | Java KeyStore Type. (`pkcs12` and `jks` are supported). Case insensitive.     | pkcs12                                                |
| `keyAlias`         | Alias for the Private Key entry                                               | spiffe                                                |
| `spiffeSocketPath` | Path the Workload API                                                         | Read from the system variable: SPIFFE_ENDPOINT_SOCKET |

KeyStore and TrustStore **must** be in separate files. If `keyStorePath` and `trustStorePath` points to the same file,
an error is shown. 
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

Trusted certificate aliases have the form `<trust-domain>.<numeric-index>`, for example `example.org.0`.
The index consists entirely of ASCII digits. Certificate entries matching this format are managed by the Helper;
reserve these aliases for Workload API bundles. Other aliases and private key entries are preserved.
If a private-key entry uses an alias needed by a bundle, the trust update fails and preserves the key. The identity
KeyStore may already have been written when this failure occurs.

Each X.509 context update replaces all Helper-managed authorities with the complete bundle set, removing stale indexes
and authorities for trust domains no longer present. The replacement is prepared in a separate in-memory KeyStore and
the TrustStore is written once per update. If preparing or serializing the replacement fails, the live in-memory
TrustStore and existing file remain unchanged. The replacement becomes the live store only after the write succeeds.
The private key entry in the KeyStore is updated the same way. If any update fails, including an I/O failure while
writing the file, the live in-memory store keeps its previous entries, so a later successful write does not persist
the failed update.

Files are still written in place, so an I/O failure or crash during writing can leave a partial file. The KeyStore and
TrustStore are written separately; the two files are not updated atomically together.
