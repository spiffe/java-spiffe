package io.spiffe.helper.keystore;

import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.workloadapi.DefaultWorkloadApiClient;
import io.spiffe.workloadapi.Watcher;
import io.spiffe.workloadapi.WorkloadApiClient;
import io.spiffe.workloadapi.X509Context;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.Setter;
import lombok.SneakyThrows;
import lombok.extern.java.Log;
import lombok.val;
import org.apache.commons.lang3.StringUtils;

import java.io.Closeable;
import java.nio.file.Path;
import java.security.KeyStoreException;
import java.util.concurrent.CountDownLatch;
import java.util.logging.Level;

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
@Log
public class KeyStoreHelper implements Closeable {

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


    /**
     * Constructor.
     * <p>
     * Creates an instance of a KeyStoreHelper for fetching X.509 SVIDs and bundles
     * from a Workload API and store them in a binary Java KeyStore in disk.
     * <p>
     * It blocks until the initial update has been received from the Workload API.
     *
     * @param options an instance of {@link KeyStoreOptions}
     * @throws SocketEndpointAddressException is the socket endpoint address is not valid
     * @throws KeyStoreException              is the entry cannot be stored in the KeyStore
     */
    public KeyStoreHelper(@NonNull final KeyStoreOptions options)
            throws SocketEndpointAddressException, KeyStoreException {

        final KeyStoreType keyStoreType;
        if (options.keyStoreType == null) {
            keyStoreType = KeyStoreType.getDefaultType();
        } else {
            keyStoreType = options.keyStoreType;
        }

        this.keyPass = options.keyPass;

        if (StringUtils.isBlank(options.keyAlias)) {
            this.keyAlias = DEFAULT_ALIAS;
        } else {
            this.keyAlias = options.keyAlias;
        }

        if (options.keyStorePath.equals(options.trustStorePath)) {
            throw new KeyStoreException("KeyStore and TrustStore should use different files");
        }

        this.keyStore = KeyStore.builder()
                .keyStoreFilePath(options.keyStorePath)
                .keyStoreType(keyStoreType)
                .keyStorePassword(options.keyStorePass)
                .build();

        this.trustStore = KeyStore.builder()
                .keyStoreFilePath(options.trustStorePath)
                .keyStoreType(keyStoreType)
                .keyStorePassword(options.trustStorePass)
                .build();

        if (options.workloadApiClient != null) {
            workloadApiClient = options.workloadApiClient;
        } else {
            workloadApiClient = createNewClient(options.spiffeSocketPath);
        }

        setX509ContextWatcher(workloadApiClient);
    }

    @SneakyThrows
    @Override
    public void close() {
        workloadApiClient.close();
    }


    private WorkloadApiClient createNewClient(final String spiffeSocketPath) throws SocketEndpointAddressException {
        val clientOptions = DefaultWorkloadApiClient.ClientOptions.builder().spiffeSocketPath(spiffeSocketPath).build();
        return DefaultWorkloadApiClient.newClient(clientOptions);
    }

    private void setX509ContextWatcher(final WorkloadApiClient workloadApiClient) {
        val countDownLatch = new CountDownLatch(1);
        workloadApiClient.watchX509Context(new Watcher<X509Context>() {
            @Override
            public void onUpdate(X509Context update) {
                try {
                    storeX509ContextUpdate(update);
                } catch (KeyStoreException e) {
                    this.onError(e);
                }
                countDownLatch.countDown();
            }

            @Override
            public void onError(Throwable t) {
                log.log(Level.SEVERE, "Error processing X.509 context update", t);
            }
        });

        await(countDownLatch);
    }

    private void storeX509ContextUpdate(final X509Context update) throws KeyStoreException {
        val privateKeyEntry = PrivateKeyEntry.builder()
                .alias(keyAlias)
                .password(keyPass)
                .privateKey(update.getDefaultSvid().getPrivateKey())
                .certificateChain(update.getDefaultSvid().getChainArray())
                .build();

        keyStore.storePrivateKeyEntry(privateKeyEntry);

        for (val entry : update.getX509BundleSet().getBundles().entrySet()) {
            TrustDomain trustDomain = entry.getKey();
            X509Bundle bundle = entry.getValue();
            storeBundle(trustDomain, bundle);
        }

        log.log(Level.INFO, "Stored X.509 context update in Java KeyStore");
    }

    private void storeBundle(final TrustDomain trustDomain, final X509Bundle bundle) throws KeyStoreException {
        int index = 0;
        for (val certificate : bundle.getX509Authorities()) {
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
     * <code>keyStorePath</code> Absolute path to File storing the Key Store. Cannot be null.
     * <p>
     * <code>trustStorePath</code> Absolute path to File storing the Trust Store. Cannot be null.
     * <p>
     * <code>keyStoreType</code>
     * The type of keystore. Only JKS and PKCS12 are supported. If it's not provided, PKCS12 is used
     * See the KeyStore section in the <a href=
     * "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyStore">
     * Java Cryptography Architecture Standard Algorithm Name Documentation</a>
     * for information about standard keystore types.
     * <p>
     * The same type is used for both the KeyStore and the TrustStore.
     *
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
    @Data
    public static class KeyStoreOptions {

        @Setter(AccessLevel.NONE)
        private Path keyStorePath;

        @Setter(AccessLevel.NONE)
        private Path trustStorePath;

        @Setter(AccessLevel.NONE)
        private KeyStoreType keyStoreType;

        @Setter(AccessLevel.NONE)
        private String keyStorePass;

        @Setter(AccessLevel.NONE)
        private String trustStorePass;

        @Setter(AccessLevel.NONE)
        private String keyPass;

        @Setter(AccessLevel.NONE)
        private String keyAlias;

        @Setter(AccessLevel.NONE)
        private String spiffeSocketPath;

        @Setter(AccessLevel.NONE)
        private WorkloadApiClient workloadApiClient;

        @Builder
        public KeyStoreOptions(@NonNull final Path keyStorePath,
                               @NonNull final Path trustStorePath,
                               @NonNull final String keyStorePass,
                               @NonNull final String trustStorePass,
                               @NonNull final String keyPass,
                               final KeyStoreType keyStoreType,
                               final String keyAlias,
                               final WorkloadApiClient workloadApiClient,
                               final String spiffeSocketPath) {
            this.keyStorePath = keyStorePath;
            this.trustStorePath = trustStorePath;
            this.keyStoreType = keyStoreType;
            this.keyStorePass = keyStorePass;
            this.trustStorePass = trustStorePass;
            this.keyPass = keyPass;
            this.keyAlias = keyAlias;
            this.workloadApiClient = workloadApiClient;
            this.spiffeSocketPath = spiffeSocketPath;
        }
    }
}
