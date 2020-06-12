package spiffe.provider;

import lombok.NonNull;
import spiffe.bundle.BundleSource;
import spiffe.bundle.x509bundle.X509Bundle;
import spiffe.exception.SocketEndpointAddressException;
import spiffe.exception.X509SourceException;
import spiffe.spiffeid.SpiffeId;
import spiffe.spiffeid.SpiffeIdUtils;
import spiffe.workloadapi.X509Source;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import java.security.KeyStore;
import java.util.List;
import java.util.function.Supplier;

import static spiffe.provider.SpiffeProviderConstants.SSL_SPIFFE_ACCEPT_ALL_PROPERTY;
import static spiffe.provider.SpiffeProviderConstants.SSL_SPIFFE_ACCEPT_PROPERTY;

/**
 * A <code>SpiffeTrustManagerFactory</code> is an implementation of a {@link javax.net.ssl.TrustManagerFactory} to create a
 * TrustManager backed by a X509BundleSource that is maintained via the Workload API.
 * <p>
 * The JSSE API will call engineGetTrustManagers() to get an instance of a TrustManager. This TrustManager
 * instance gets injected a X509Source, which implements X509BundleSource and keeps bundles updated. The TrustManager
 * also gets a Supplier of a List of accepted SPIFFE IDs.
 *
 * @see SpiffeSslContextFactory
 * @see BundleSource
 * @see X509SourceManager
 * @see SpiffeSslContextFactory
 */
public class SpiffeTrustManagerFactory extends TrustManagerFactorySpi {

    private static final boolean ACCEPT_ANY_SPIFFE_ID;
    private static final Supplier<List<SpiffeId>> DEFAULT_SPIFFE_ID_LIST_SUPPLIER;

    static {
        ACCEPT_ANY_SPIFFE_ID = Boolean.parseBoolean(EnvironmentUtils.getProperty(SSL_SPIFFE_ACCEPT_ALL_PROPERTY, "false"));
        DEFAULT_SPIFFE_ID_LIST_SUPPLIER = () -> SpiffeIdUtils.toListOfSpiffeIds(EnvironmentUtils.getProperty(SSL_SPIFFE_ACCEPT_PROPERTY));
    }

    /**
     * Default method for creating a TrustManager initializing it with
     * the {@link spiffe.workloadapi.X509Source} instance
     * that is handled by the {@link X509SourceManager}, and
     * with and a supplier of accepted SPIFFE IDs. that reads the list
     * from the System Property defined in SSL_SPIFFE_ACCEPT_PROPERTY.
     *
     * @return a {@link TrustManager} array with an initialized TrustManager.
     * @throws SpiffeProviderException in case there is an error setting up the X.509 source
     */
    @Override
    public TrustManager[] engineGetTrustManagers() {

        X509Source x509Source;
        try {
            x509Source = X509SourceManager.getX509Source();
        } catch (X509SourceException e) {
            throw new SpiffeProviderException("The X.509 source could not be created", e);
        } catch (SocketEndpointAddressException e) {
            throw new SpiffeProviderException("The Workload API Socket endpoint address configured is not valid", e);
        }

        SpiffeTrustManager spiffeTrustManager;
        if (ACCEPT_ANY_SPIFFE_ID) {
            spiffeTrustManager = new SpiffeTrustManager(x509Source, true);
        } else {
            spiffeTrustManager = new SpiffeTrustManager(x509Source, DEFAULT_SPIFFE_ID_LIST_SUPPLIER);
        }
        return new TrustManager[]{spiffeTrustManager};
    }

    /**
     * Creates a {@link TrustManager} initializing it with the X.509 BundleSource instance
     * and with and a supplier of accepted SPIFFE IDs. that reads the list
     * from the System Property defined in SSL_SPIFFE_ACCEPT_PROPERTY.
     *
     * @return a TrustManager array with an initialized TrustManager.
     */
    public TrustManager[] engineGetTrustManagers(@NonNull BundleSource<X509Bundle> x509BundleSource) {
        SpiffeTrustManager spiffeTrustManager;

        if (ACCEPT_ANY_SPIFFE_ID) {
            // make explicit that all SPIFFE IDs will be accepted
            spiffeTrustManager = new SpiffeTrustManager(x509BundleSource, true);
        } else {
            spiffeTrustManager = new SpiffeTrustManager(x509BundleSource, DEFAULT_SPIFFE_ID_LIST_SUPPLIER);
        }
        return new TrustManager[]{spiffeTrustManager};
    }

    /**
     * Creates a {@link TrustManager} initializing it with the X.509 BundleSource instance.
     * The TrustManager is configured to accept any SPIFFE ID.
     *
     * @return a TrustManager array with an initialized TrustManager.
     */
    public TrustManager[] engineGetTrustManagersAcceptAnySpiffeId(@NonNull BundleSource<X509Bundle> x509BundleSource) {
        SpiffeTrustManager spiffeTrustManager = new SpiffeTrustManager(x509BundleSource, true);
        return new TrustManager[]{spiffeTrustManager};
    }

    /**
     * Creates a TrustManager initializing it with a X509BundleSource to get the bundles,
     * with a function verify a chain of certificates using a to validate the SPIFFE IDs
     * of the peer's certificates, and a supplier of accepted SPIFFE IDs.
     *
     * @param x509BundleSource          a {@link BundleSource} to provide the X.509-Bundles
     * @param acceptedSpiffeIdsSupplier a Supplier to provide a List of SPIFFE IDs that are accepted
     * @return a TrustManager array with an initialized TrustManager.
     */
    public TrustManager[] engineGetTrustManagers(
            @NonNull BundleSource<X509Bundle> x509BundleSource,
            @NonNull Supplier<List<SpiffeId>> acceptedSpiffeIdsSupplier) {

        SpiffeTrustManager spiffeTrustManager = new SpiffeTrustManager(x509BundleSource, acceptedSpiffeIdsSupplier);
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
}
