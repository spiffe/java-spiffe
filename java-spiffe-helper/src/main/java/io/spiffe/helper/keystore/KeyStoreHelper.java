package io.spiffe.helper.keystore;

import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.workloadapi.Watcher;
import io.spiffe.workloadapi.WorkloadApiClient;
import io.spiffe.workloadapi.X509Context;
import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.extern.java.Log;
import lombok.val;
import org.apache.commons.lang3.StringUtils;

import java.io.Closeable;
import java.nio.file.Path;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.logging.Level;

/**
 * Represents a helper for storing X.509 SVIDs and bundles that are automatically fetched and rotated via the Workload API,
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
    public KeyStoreHelper(@NonNull final KeyStoreOptions options) throws SocketEndpointAddressException, KeyStoreException {

        KeyStoreType keyStoreType;
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

        if (options.client != null) {
            workloadApiClient = options.client;
        } else {
            workloadApiClient = createNewClient(options.spiffeSocketPath);
        }

        setX509ContextWatcher(workloadApiClient);
    }

    private WorkloadApiClient createNewClient(final String spiffeSocketPath) throws SocketEndpointAddressException {
        WorkloadApiClient.ClientOptions clientOptions = WorkloadApiClient.ClientOptions.builder().spiffeSocketPath(spiffeSocketPath).build();
        return WorkloadApiClient.newClient(clientOptions);
    }

    private void setX509ContextWatcher(WorkloadApiClient workloadApiClient) {
        CountDownLatch countDownLatch = new CountDownLatch(1);
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

        for (Map.Entry<TrustDomain, X509Bundle> entry : update.getX509BundleSet().getBundles().entrySet()) {
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

    private String generateAlias(TrustDomain trustDomain, int index) {
        return trustDomain.getName().concat(".").concat(String.valueOf(index));
    }

    private void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public void close() {
        workloadApiClient.close();
    }

    /**
     * Options for creating a KeyStoreHelper.
     */
    @Data
    public static class KeyStoreOptions {

        /**
         * Absolute path to File storing the Key Store. Cannot be null.
         */
        Path keyStorePath;

        /**
         * Absolute path to File storing the Trust Store. Cannot be null.
         */
        Path trustStorePath;

        /**
         * The type of keystore. Only JKS and PKCS12 are supported. If it's not provided, PKCS12 is used
         * See the KeyStore section in the <a href=
         * "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyStore">
         * Java Cryptography Architecture Standard Algorithm Name Documentation</a>
         * for information about standard keystore types.
         * <p>
         * The same type is used for both the KeyStore and the TrustStore.
         *
         * Optional. Default is PKCS12.
         */
        KeyStoreType keyStoreType;

        /**
         * The password to generate the keystore integrity check.
         */
        String keyStorePass;

        /**
         * The password to generate the truststore integrity check.
         */
        String trustStorePass;

        /**
         * The password to protect the key.
         */
        String keyPass;

        /**
         * Alias of the keyEntry. Default: spiffe
         * Note: java keystore aliases are case-insensitive.
         */
        String keyAlias;

        /**
         * Optional spiffeSocketPath, if absent, SPIFFE_ENDPOINT_SOCKET env variable is used.
         */
        String spiffeSocketPath;

        /**
         * Optional. The workload api client to fetch the X.509 materials from the Workload API.
         */
        WorkloadApiClient client;

        @Builder
        public KeyStoreOptions(@NonNull Path keyStorePath, @NonNull Path trustStorePath, @NonNull String keyStorePass,
                               @NonNull String trustStorePass, @NonNull String keyPass, KeyStoreType keyStoreType,
                               String keyAlias, WorkloadApiClient client, String spiffeSocketPath) {
            this.keyStorePath = keyStorePath;
            this.trustStorePath = trustStorePath;
            this.keyStoreType = keyStoreType;
            this.keyStorePass = keyStorePass;
            this.trustStorePass = trustStorePass;
            this.keyPass = keyPass;
            this.keyAlias = keyAlias;
            this.client = client;
            this.spiffeSocketPath = spiffeSocketPath;
        }
    }
}
