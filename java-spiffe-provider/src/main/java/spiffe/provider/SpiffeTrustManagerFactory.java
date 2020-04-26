package spiffe.provider;

import lombok.val;
import spiffe.bundle.x509bundle.X509BundleSource;
import spiffe.spiffeid.SpiffeId;
import spiffe.spiffeid.SpiffeIdUtils;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import java.security.KeyStore;
import java.util.List;
import java.util.function.Supplier;

/**
 * A <code>SpiffeTrustManagerFactory</code> is an implementation of a {@link javax.net.ssl.TrustManagerFactory} to create a
 * TrustManager backed by a X509BundleSource that is maintained via the Workload API.
 * <p>
 * The JSSE API will call engineGetTrustManagers() to get an instance of a TrustManager. This TrustManager
 * instance gets injected a X509Source, which implements X509BundleSource and keeps bundles updated. The TrustManager
 * also gets a Supplier of a List of accepted SPIFFE IDs.
 *
 * @see SpiffeSslContextFactory
 * @see X509BundleSource
 * @see X509SourceManager
 * @see SpiffeSslContextFactory
 */
public class SpiffeTrustManagerFactory extends TrustManagerFactorySpi {

    // System property to get the list of accepted SPIFFE IDs
    private static final String SSL_SPIFFE_ACCEPT_PROPERTY = "ssl.spiffe.accept";

    /**
     * Default method for creating a TrustManager initializing it with
     * the {@link spiffe.workloadapi.X509Source} instance
     * that is handled by the {@link X509SourceManager}, and
     * with and a supplier of accepted SPIFFE IDs. that reads the list
     * from the System Property defined in SSL_SPIFFE_ACCEPT_PROPERTY.
     *
     * @return a TrustManager array with an initialized TrustManager.
     */
    @Override
    public TrustManager[] engineGetTrustManagers() {
        val spiffeTrustManager =
                new SpiffeTrustManager(
                        X509SourceManager.INSTANCE.getX509Source(),
                        this::getAcceptedSpiffeIds
                );
        return new TrustManager[]{spiffeTrustManager};
    }

    /**
     * Creates a TrustManager initializing it with the X509BundleSource instance
     * and with and a supplier of accepted SPIFFE IDs. that reads the list
     * from the System Property defined in SSL_SPIFFE_ACCEPT_PROPERTY.
     *
     * @return a TrustManager array with an initialized TrustManager.
     */
    public TrustManager[] engineGetTrustManagers(X509BundleSource x509BundleSource) {
        val spiffeTrustManager =
                new SpiffeTrustManager(
                        x509BundleSource,
                        this::getAcceptedSpiffeIds
                );
        return new TrustManager[]{spiffeTrustManager};
    }

    /**
     * Creates a TrustManager initializing it with a X509BundleSource to get the bundles,
     * with a function verify a chain of certificates using a to validate the SPIFFE IDs
     * of the peer's certificates, and a supplier of accepted SPIFFE IDs.
     *
     * @param x509BundleSource a {@link X509BundleSource} to provide the X509-Bundles
     * @param acceptedSpiffeIdsSupplier a Supplier to provide a List of SPIFFE IDs that are accepted
     * @return a TrustManager array with an initialized TrustManager.
     */
    public TrustManager[] engineGetTrustManagers(
            X509BundleSource x509BundleSource,
            Supplier<List<SpiffeId>> acceptedSpiffeIdsSupplier) {

        Supplier<List<SpiffeId>> spiffeIdsSupplier;
        if (acceptedSpiffeIdsSupplier != null) {
            spiffeIdsSupplier = acceptedSpiffeIdsSupplier;
        } else {
            spiffeIdsSupplier = this::getAcceptedSpiffeIds;
        }
        val spiffeTrustManager =
                new SpiffeTrustManager(
                        x509BundleSource,
                        spiffeIdsSupplier
                );
        return new TrustManager[]{spiffeTrustManager};
    }

    @Override
    protected void engineInit(KeyStore keyStore) {
        // no implementation needed
    }

    @Override
    protected void engineInit(ManagerFactoryParameters managerFactoryParameters) {
        // no implementation needed
    }


    private List<SpiffeId> getAcceptedSpiffeIds() {
        return SpiffeIdUtils.getSpiffeIdsFromSecurityProperty(SSL_SPIFFE_ACCEPT_PROPERTY);
    }
}
