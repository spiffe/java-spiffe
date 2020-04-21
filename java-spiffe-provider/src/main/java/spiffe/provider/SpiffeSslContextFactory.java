package spiffe.provider;

import lombok.val;
import spiffe.bundle.x509bundle.X509BundleSource;
import spiffe.result.Result;
import spiffe.spiffeid.SpiffeId;
import spiffe.svid.x509svid.X509SvidSource;
import spiffe.workloadapi.Address;
import spiffe.workloadapi.X509Source;

import javax.net.ssl.SSLContext;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.function.Supplier;

/**
 * Utility class to create instances of {@link SSLContext} initialized
 * with a {@link SpiffeKeyManager} and a {@link SpiffeTrustManager} that
 * are backed by the Workload API.
 */
public final class SpiffeSslContextFactory {

    private static final String DEFAULT_SSL_PROTOCOL = "TLSv1.2";

    /**
     * Creates an SSLContext initialized with a SPIFFE KeyManager and TrustManager that are backed by
     * the Workload API via a X509Source.
     *
     * The TrustManager uses {@link spiffe.svid.x509svid.X509SvidValidator} to validate chain and check the SPIFFE ID,
     * and {@link spiffe.spiffeid.SpiffeIdUtils} to get the list of accepted SPIFFE IDs from a System variable.
     *
     * @implNote the environment variable <code>SpiffeConstants.SOCKET_ENV_VARIABLE</code> should be set with
     * the path to the Workload API endpoint.
     *
     * @return a SSLContext
     */
    public static SSLContext getSslContext() {
        try {
            val sslContext = SSLContext.getInstance(DEFAULT_SSL_PROTOCOL);
            sslContext.init(
                    new SpiffeKeyManagerFactory().engineGetKeyManagers(),
                    new SpiffeTrustManagerFactory().engineGetTrustManagers(),
                    null);
            return sslContext;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Creates an SSLContext initialized with a SPIFFE KeyManager and TrustManager,
     * providing a supplier of the SPIFFE IDs that will be accepted during peer's SVID validation,
     * and using an environment variable to get the Path to the SPIFFE Socket endpoint.
     *
     * @param acceptedSpiffeIdsSupplier a supplier of a list of accepted SPIFFE IDs
     * @return an SSLContext initialized with a SpiffeKeyManager and a SpiffeTrustManager.
     */
    public static SSLContext getSslContext(Supplier<Result<List<SpiffeId>, String>> acceptedSpiffeIdsSupplier) {
        val spiffeSocketPath = System.getenv(Address.SOCKET_ENV_VARIABLE);
        return getSslContext(spiffeSocketPath, acceptedSpiffeIdsSupplier);

    }

    /**
     * Creates an SSLContext initialized with a SPIFFE KeyManager and TrustManager,
     * specifying the Path where the Workload API is listening, and a supplier of
     * the SPIFFE IDs that will be accepted during peer's SVID validation.
     *
     * @param spiffeSocketPath a Path to the Workload API endpoint
     * @param acceptedSpiffeIdsSupplier a supplier of a list of accepted SPIFFE IDs
     * @return an SSLContext initialized with a SpiffeKeyManager and a SpiffeTrustManager.
     */
    public static SSLContext getSslContext(
            String spiffeSocketPath,
            Supplier<Result<List<SpiffeId>, String>> acceptedSpiffeIdsSupplier) {
        try {
            val sslContext = SSLContext.getInstance(DEFAULT_SSL_PROTOCOL);
            Result<X509Source, String> x509Source = X509Source.newSource(spiffeSocketPath);
            if (x509Source.isError()) {
                throw new RuntimeException(x509Source.getError());
            }

            sslContext.init(
                    new SpiffeKeyManagerFactory().engineGetKeyManagers(x509Source.getValue()),
                    new SpiffeTrustManagerFactory()
                            .engineGetTrustManagers(
                                    x509Source.getValue(),
                                    acceptedSpiffeIdsSupplier),
                    null);
            return sslContext;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Creates an SSLContext initialized with a SPIFFE KeyManager and TrustManager.
     *
     * @param x509SvidSource a {@link X509SvidSource} to provide the X509-SVIDs
     * @param x509BundleSource a {@link X509BundleSource} to provide Bundles to validate SVIDs
     * @param acceptedSpiffeIdsSupplier a supplier of a list of accepted SPIFFE IDs
     * @return an SSLContext
     */
    public static SSLContext getSslContext(
            X509SvidSource x509SvidSource,
            X509BundleSource x509BundleSource,
            Supplier<Result<List<SpiffeId>, String>> acceptedSpiffeIdsSupplier) {
        try {
            val sslContext = SSLContext.getInstance(DEFAULT_SSL_PROTOCOL);
            sslContext.init(
                    new SpiffeKeyManagerFactory().engineGetKeyManagers(x509SvidSource),
                    new SpiffeTrustManagerFactory()
                            .engineGetTrustManagers(
                                    x509BundleSource,
                                    acceptedSpiffeIdsSupplier),
                    null);
            return sslContext;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IllegalStateException(e);
        }
    }
}
