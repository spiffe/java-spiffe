package io.spiffe.helper.keystore;

import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.exception.WatcherException;
import io.spiffe.helper.exception.KeyStoreHelperException;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.workloadapi.DefaultWorkloadApiClient;
import io.spiffe.workloadapi.Watcher;
import io.spiffe.workloadapi.WorkloadApiClient;
import io.spiffe.workloadapi.X509Context;
import org.apache.commons.lang3.StringUtils;

import java.io.Closeable;
import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Helper for storing X.509 SVIDs and bundles that are automatically fetched and rotated via the Workload API,
 * in a Java KeyStore and a TrustStore in files in disk.
 * <p>
 * It stores the Private Key along with the chain of X.509 certificates in a KeyStore, and the
 * trusted bundles in a separate KeyStore (TrustStore).
 * <p>
 * The underlying workload api client uses a backoff retry policy to reconnect to the Workload API
 * when the connection is lost.
 */
public class KeyStoreHelper implements Closeable {

    private static final Logger log =
            Logger.getLogger(KeyStoreHelper.class.getName());

    // case insensitive private key default alias
    static final String DEFAULT_ALIAS = "spiffe";

    // stores private key and chain of certificates
    private final KeyStore keyStore;

    // stores trusted bundles
    private final KeyStore trustStore;

    // password that protects the private key
    private final String keyPass;

    // alias of the private key entry (case-insensitive)
    private final String keyAlias;

    private final WorkloadApiClient workloadApiClient;

    private volatile boolean closed;
    private volatile CountDownLatch countDownLatch;

    /**
     * Creates an instance of a KeyStoreHelper for fetching X.509 SVIDs and bundles
     * from a Workload API and store them in a binary Java KeyStore in disk.
     *
     * @param options an instance of {@link KeyStoreOptions}
     * @return an instance of a KeyStoreHelper
     * @throws SocketEndpointAddressException if the socket endpoint address is not valid
     * @throws KeyStoreHelperException        if the KeyStoreHelper cannot be created
     * @throws KeyStoreException if the underlying java KeyStore and TrustStore cannot be created
     */
    public static KeyStoreHelper create(KeyStoreOptions options) throws SocketEndpointAddressException, KeyStoreHelperException, KeyStoreException {
        Objects.requireNonNull(options, "options must not be null");

        if (options.keyStorePath.equals(options.trustStorePath)) {
            throw new KeyStoreHelperException("KeyStore and TrustStore should use different files");
        }

        if (options.keyStoreType == null) {
            options.keyStoreType = KeyStoreType.getDefaultType();
        }

        if (StringUtils.isBlank(options.keyAlias)) {
            options.keyAlias = DEFAULT_ALIAS;
        }

        final KeyStore keyStore = createKeyStore(options, options.keyStorePath, options.keyStorePass);
        final KeyStore trustStore = createKeyStore(options, options.trustStorePath, options.trustStorePass);

        if (options.workloadApiClient == null) {
            options.workloadApiClient = createNewClient(options.spiffeSocketPath);
        }

        return new KeyStoreHelper(keyStore, trustStore, options.keyPass, options.keyAlias, options.workloadApiClient);
    }

    /**
     * Sets the instance to run fetching and storing the X.509 SVIDs and Bundles.
     *
     * @param keepRunning if true, the process will block receiving and storing updates, otherwise it blocks only until
     *                    the first X.509 context is received and stored.
     * @throws KeyStoreHelperException if there is an error fetching or storing the X.509 SVIDs and Bundles
     */
    public void run(boolean keepRunning) throws KeyStoreHelperException {
        if (isClosed()) {
            throw new IllegalStateException("KeyStoreHelper is closed");
        }

        try {
            this.setX509ContextWatcher(keepRunning);
        } catch (Exception e) {
            throw new KeyStoreHelperException("Error running KeyStoreHelper", e);
        }
    }

    /**
     * Closes the KeyStoreHelper instance.
     */
    @Override
    public void close() {
        if (!closed) {
            synchronized (this) {
                if (!closed) {
                    try {
                        workloadApiClient.close();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                    countDown();
                    closed = true;
                    log.info("KeyStoreHelper is closed");
                }
            }
        }
    }

    private void countDown() {
        if (countDownLatch != null) {
            countDownLatch.countDown();
        }
    }

    private KeyStoreHelper(KeyStore keyStore, KeyStore trustStore, String keyPass, String keyAlias, WorkloadApiClient workloadApiClient) {
        this.keyStore = keyStore;
        this.trustStore = trustStore;
        this.keyPass = keyPass;
        this.keyAlias = keyAlias;
        this.workloadApiClient = workloadApiClient;
    }

    private static KeyStore createKeyStore(KeyStoreOptions options, Path keyStorePath, String keyStorePass) throws KeyStoreException {
        return KeyStore.builder()
                .keyStoreFilePath(keyStorePath)
                .keyStoreType(options.keyStoreType)
                .keyStorePassword(keyStorePass)
                .build();
    }

    private static WorkloadApiClient createNewClient(final String spiffeSocketPath) throws SocketEndpointAddressException {
        final DefaultWorkloadApiClient.ClientOptions clientOptions = DefaultWorkloadApiClient.ClientOptions.builder().spiffeSocketPath(spiffeSocketPath).build();
        return DefaultWorkloadApiClient.newClient(clientOptions);
    }

    private void setX509ContextWatcher(boolean keepRunning) {
        countDownLatch = new CountDownLatch(1);
        workloadApiClient.watchX509Context(new Watcher<X509Context>() {
            @Override
            public void onUpdate(X509Context update) {
                try {
                    storeX509ContextUpdate(update);
                    if (!keepRunning) {
                        // got a X509 update, process is complete
                        countDownLatch.countDown();
                    }
                } catch (KeyStoreException e) {
                    this.onError(e);
                }
            }

            @Override
            public void onError(Throwable e) {
                log.log(Level.SEVERE, e.getMessage());
                countDownLatch.countDown();
                throw new WatcherException("Error processing X.509 context update", e);
            }
        });

        await(countDownLatch);
    }

    private void storeX509ContextUpdate(final X509Context update) throws KeyStoreException {
        final PrivateKeyEntry privateKeyEntry = PrivateKeyEntry.builder()
                .alias(keyAlias)
                .password(keyPass)
                .privateKey(update.getDefaultSvid().getPrivateKey())
                .certificateChain(update.getDefaultSvid().getChainArray())
                .build();

        keyStore.storePrivateKeyEntry(privateKeyEntry);

        for (final Map.Entry<TrustDomain, X509Bundle> entry : update.getX509BundleSet().getBundles().entrySet()) {
            TrustDomain trustDomain = entry.getKey();
            X509Bundle bundle = entry.getValue();
            storeBundle(trustDomain, bundle);
        }

        log.log(Level.INFO, "Stored X.509 context update in Java KeyStore");
    }

    private void storeBundle(TrustDomain trustDomain, X509Bundle bundle) throws KeyStoreException {
        int index = 0;
        for (X509Certificate certificate : bundle.getX509Authorities()) {
            final AuthorityEntry authorityEntry = AuthorityEntry.builder()
                    .alias(generateAlias(trustDomain, index))
                    .certificate(certificate)
                    .build();
            trustStore.storeAuthorityEntry(authorityEntry);
        }
    }

    private String generateAlias(final TrustDomain trustDomain, int index) {
        return trustDomain.getName().concat(".").concat(String.valueOf(index));
    }

    private boolean isClosed() {
        synchronized (this) {
            return closed;
        }
    }

    private void await(final CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Options for creating a {@link KeyStoreHelper}.
     * <p>
     * <code>keyStorePath</code> Absolute path to File storing the Key Store. must not be null.
     * <p>
     * <code>trustStorePath</code> Absolute path to File storing the Trust Store. must not be null.
     * <p>
     * <code>keyStoreType</code>
     * The type of keystore. Only JKS and PKCS12 are supported. If it's not provided, PKCS12 is used
     * See the KeyStore section in the <a href=
     * "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyStore">
     * Java Cryptography Architecture Standard Algorithm Name Documentation</a>
     * for information about standard keystore types.
     * <p>
     * The same type is used for both the KeyStore and the TrustStore.
     * <p>
     * Optional. Default is PKCS12.
     * <p>
     * <code>keyStorePass</code> The password to generate the keystore integrity check.
     * <p>
     * <code>trustStorePass</code> The password to generate the truststore integrity check.
     * <p>
     * <code>keyPass</code> The password to protect the key.
     * <p>
     * <code>keyAlias</code> Alias of the keyEntry. Default: spiffe
     * Note: java keystore aliases are case-insensitive.
     * <p>
     * <code>spiffeSocketPath</code> Optional SPIFFE Endpoint Socket address,
     * if absent, SPIFFE_ENDPOINT_SOCKET env variable is used.
     * <p>
     * <code>client</code> Optional. The a {@link WorkloadApiClient} to fetch the X.509 materials from the Workload API.
     */
    public static class KeyStoreOptions {

        private Path keyStorePath;
        private Path trustStorePath;
        private KeyStoreType keyStoreType;
        private String keyStorePass;
        private String trustStorePass;
        private String keyPass;
        private String keyAlias;
        private String spiffeSocketPath;
        private WorkloadApiClient workloadApiClient;

        public KeyStoreOptions(Path keyStorePath,
                               Path trustStorePath,
                               String keyStorePass,
                               String trustStorePass,
                               String keyPass,
                               KeyStoreType keyStoreType,
                               String keyAlias,
                               WorkloadApiClient workloadApiClient,
                               String spiffeSocketPath) {

            this.keyStorePath = Objects.requireNonNull(keyStorePath, "keyStorePath must not be null");
            this.trustStorePath = Objects.requireNonNull(trustStorePath, "trustStorePath must not be null");
            this.keyStorePass = Objects.requireNonNull(keyStorePass, "keyStorePass must not be null");
            this.trustStorePass = Objects.requireNonNull(trustStorePass, "trustStorePass must not be null");
            this.keyPass = Objects.requireNonNull(keyPass, "keyPass must not be null");
            this.keyStoreType = keyStoreType;
            this.keyAlias = keyAlias;
            this.workloadApiClient = workloadApiClient;
            this.spiffeSocketPath = spiffeSocketPath;
        }

        public static Builder builder() {
            return new Builder();
        }

        public static final class Builder {
            private Path keyStorePath;
            private Path trustStorePath;
            private KeyStoreType keyStoreType;
            private String keyStorePass;
            private String trustStorePass;
            private String keyPass;
            private String keyAlias;
            private String spiffeSocketPath;
            private WorkloadApiClient workloadApiClient;

            public Builder keyStorePath(Path keyStorePath) {
                this.keyStorePath = keyStorePath;
                return this;
            }

            public Builder trustStorePath(Path trustStorePath) {
                this.trustStorePath = trustStorePath;
                return this;
            }

            public Builder keyStorePass(String keyStorePass) {
                this.keyStorePass = keyStorePass;
                return this;
            }

            public Builder trustStorePass(String trustStorePass) {
                this.trustStorePass = trustStorePass;
                return this;
            }

            public Builder keyPass(String keyPass) {
                this.keyPass = keyPass;
                return this;
            }

            public Builder keyStoreType(KeyStoreType keyStoreType) {
                this.keyStoreType = keyStoreType;
                return this;
            }

            public Builder keyAlias(String keyAlias) {
                this.keyAlias = keyAlias;
                return this;
            }

            public Builder workloadApiClient(WorkloadApiClient workloadApiClient) {
                this.workloadApiClient = workloadApiClient;
                return this;
            }

            public Builder spiffeSocketPath(String spiffeSocketPath) {
                this.spiffeSocketPath = spiffeSocketPath;
                return this;
            }

            public KeyStoreOptions build() {
                return new KeyStoreOptions(
                        keyStorePath,
                        trustStorePath,
                        keyStorePass,
                        trustStorePass,
                        keyPass,
                        keyStoreType,
                        keyAlias,
                        workloadApiClient,
                        spiffeSocketPath
                );
            }
        }

        public Path getKeyStorePath() {
            return keyStorePath;
        }

        public Path getTrustStorePath() {
            return trustStorePath;
        }

        public KeyStoreType getKeyStoreType() {
            return keyStoreType;
        }

        public String getKeyStorePass() {
            return keyStorePass;
        }

        public String getTrustStorePass() {
            return trustStorePass;
        }

        public String getKeyPass() {
            return keyPass;
        }

        public String getKeyAlias() {
            return keyAlias;
        }

        public String getSpiffeSocketPath() {
            return spiffeSocketPath;
        }

        public WorkloadApiClient getWorkloadApiClient() {
            return workloadApiClient;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof KeyStoreOptions)) return false;
            KeyStoreOptions that = (KeyStoreOptions) o;
            return Objects.equals(keyStorePath, that.keyStorePath)
                    && Objects.equals(trustStorePath, that.trustStorePath)
                    && Objects.equals(keyStoreType, that.keyStoreType)
                    && Objects.equals(keyStorePass, that.keyStorePass)
                    && Objects.equals(trustStorePass, that.trustStorePass)
                    && Objects.equals(keyPass, that.keyPass)
                    && Objects.equals(keyAlias, that.keyAlias)
                    && Objects.equals(spiffeSocketPath, that.spiffeSocketPath)
                    && Objects.equals(workloadApiClient, that.workloadApiClient);
        }

        @Override
        public int hashCode() {
            return Objects.hash(
                    keyStorePath,
                    trustStorePath,
                    keyStoreType,
                    keyStorePass,
                    trustStorePass,
                    keyPass,
                    keyAlias,
                    spiffeSocketPath,
                    workloadApiClient
            );
        }

        @Override
        public String toString() {
            return "KeyStoreOptions{" +
                    "keyStorePath=" + keyStorePath +
                    ", trustStorePath=" + trustStorePath +
                    ", keyStoreType=" + keyStoreType +
                    ", keyStorePass='[PROTECTED]'" +
                    ", trustStorePass='[PROTECTED]'" +
                    ", keyPass='[PROTECTED]'" +
                    ", keyAlias='" + keyAlias + '\'' +
                    ", spiffeSocketPath='" + spiffeSocketPath + '\'' +
                    ", workloadApiClient=" + workloadApiClient +
                    '}';
        }
    }
}
