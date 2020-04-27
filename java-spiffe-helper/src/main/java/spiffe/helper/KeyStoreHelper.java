package spiffe.helper;

import lombok.Builder;
import lombok.NonNull;
import lombok.extern.java.Log;
import lombok.val;
import org.apache.commons.lang3.NotImplementedException;
import org.apache.commons.lang3.StringUtils;
import spiffe.exception.SocketEndpointAddressException;
import spiffe.workloadapi.Watcher;
import spiffe.workloadapi.WorkloadApiClient;
import spiffe.workloadapi.WorkloadApiClient.ClientOptions;
import spiffe.workloadapi.X509Context;

import java.nio.file.Path;
import java.security.KeyStoreException;
import java.util.concurrent.CountDownLatch;
import java.util.logging.Level;

/**
 * A <code>KeyStoreHelper</code> represents a helper for storing X.509 SVIDs and bundles,
 * that are automatically rotated via the Workload API, in a Java KeyStore in a file in disk.
 */
@Log
public class KeyStoreHelper {

    private final spiffe.helper.KeyStore keyStore;

    private final char[] privateKeyPassword;
    private final String privateKeyAlias;

    private final String spiffeSocketPath;

    /**
     * Create an instance of a KeyStoreHelper for fetching X.509 SVIDs and bundles
     * from a Workload API and store them in a binary Java KeyStore in disk.
     * <p>
     * It blocks until the initial update has been received from the Workload API.
     *
     * @param keyStoreFilePath   path to File storing the KeyStore.
     * @param keyStoreType       the type of keystore. Only JKS and PKCS12 are supported. If it's not provided, PKCS12 is used
     *                           See the KeyStore section in the <a href=
     *                           "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyStore">
     *                           Java Cryptography Architecture Standard Algorithm Name Documentation</a>
     *                           for information about standard keystore types.
     * @param keyStorePassword   the password to generate the keystore integrity check
     * @param privateKeyPassword the password to protect the key
     * @param privateKeyAlias    the alias name
     * @param spiffeSocketPath   optional spiffeSocketPath, if absent uses SPIFFE_ENDPOINT_SOCKET env variable
     *
     * @throws SocketEndpointAddressException is the socket endpoint address is not valid
     * @throws KeyStoreException is the entry cannot be stored in the KeyStore
     * @throws RuntimeException if there is an error fetching the certificates from the Workload API
     */
    @Builder
    public KeyStoreHelper(
            @NonNull final Path keyStoreFilePath,
            @NonNull final KeyStoreType keyStoreType,
            @NonNull final char[] keyStorePassword,
            @NonNull final char[] privateKeyPassword,
            @NonNull final String privateKeyAlias,
            @NonNull String spiffeSocketPath)
            throws SocketEndpointAddressException, KeyStoreException {


        this.privateKeyPassword = privateKeyPassword.clone();
        this.privateKeyAlias = privateKeyAlias;
        this.spiffeSocketPath = spiffeSocketPath;

        this.keyStore =
                KeyStore
                        .builder()
                        .keyStoreFilePath(keyStoreFilePath)
                        .keyStoreType(keyStoreType)
                        .keyStorePassword(keyStorePassword)
                        .build();

        setupX509ContextFetcher();
    }

    private void setupX509ContextFetcher() throws SocketEndpointAddressException {
        WorkloadApiClient workloadApiClient;

        if (StringUtils.isNotBlank(spiffeSocketPath)) {
            ClientOptions clientOptions = ClientOptions.builder().spiffeSocketPath(spiffeSocketPath).build();
            workloadApiClient = WorkloadApiClient.newClient(clientOptions);
        } else {
            workloadApiClient = WorkloadApiClient.newClient();
        }

        CountDownLatch countDownLatch = new CountDownLatch(1);
        setX509ContextWatcher(workloadApiClient, countDownLatch);
        await(countDownLatch);
    }

    private void setX509ContextWatcher(WorkloadApiClient workloadApiClient, CountDownLatch countDownLatch) {
        workloadApiClient.watchX509Context(new Watcher<X509Context>() {
            @Override
            public void onUpdate(X509Context update) {
                log.log(Level.INFO, "Received X509Context update");
                try {
                    storeX509ContextUpdate(update);
                } catch (KeyStoreException e) {
                    this.onError(e);
                }
                countDownLatch.countDown();
            }

            @Override
            public void onError(Throwable t) {
                throw new RuntimeException(t);
            }
        });
    }

    private void storeX509ContextUpdate(final X509Context update) throws KeyStoreException {
        val privateKeyEntry = PrivateKeyEntry.builder()
                .alias(privateKeyAlias)
                .password(privateKeyPassword)
                .privateKey(update.getDefaultSvid().getPrivateKey())
                .certificateChain(update.getDefaultSvid().getChainArray())
                .build();

        keyStore.storePrivateKey(privateKeyEntry);

        log.log(Level.INFO, "Stored X509Context update");

        // TODO: Store all the Bundles
        throw new NotImplementedException("Bundle Storing is not implemented");
    }

    private void await(CountDownLatch countDownLatch) {
        try {
            countDownLatch.await();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
