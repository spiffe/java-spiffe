package io.spiffe.provider;

import io.spiffe.bundle.BundleSource;
import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.exception.X509SourceException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.SpiffeIdUtils;
import io.spiffe.workloadapi.X509Source;
import lombok.NonNull;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import java.security.KeyStore;
import java.util.Set;
import java.util.function.Supplier;

import static io.spiffe.provider.SpiffeProviderConstants.SSL_SPIFFE_ACCEPT_ALL_PROPERTY;
import static io.spiffe.provider.SpiffeProviderConstants.SSL_SPIFFE_ACCEPT_PROPERTY;

/**
 * Implementation of a {@link javax.net.ssl.TrustManagerFactory} to create a {@link SpiffeTrustManager} backed by a
 * {@link X509Source} that is maintained via the Workload API.
 * <p>
 * The Java Security API will call <code>engineGetTrustManagers()</code> to get an instance of a {@link TrustManager}.
 * This TrustManager instance gets injected a {@link X509Source}, which implements {@link BundleSource} and keeps bundles updated.
 * The TrustManager also gets a Supplier of a List of accepted SPIFFE IDs used to validate the SPIFFE ID from the SVID
 * presented by a peer during the handshake.
 *
 * @see SpiffeSslContextFactory
 * @see BundleSource
 * @see SpiffeSslContextFactory
 */
public class SpiffeTrustManagerFactory extends TrustManagerFactorySpi {

    private static final boolean ACCEPT_ANY_SPIFFE_ID;
    private static final Supplier<Set<SpiffeId>> DEFAULT_SPIFFE_ID_LIST_SUPPLIER;

    static {
        ACCEPT_ANY_SPIFFE_ID = Boolean.parseBoolean(EnvironmentUtils.getProperty(SSL_SPIFFE_ACCEPT_ALL_PROPERTY, "false"));
        DEFAULT_SPIFFE_ID_LIST_SUPPLIER = () -> SpiffeIdUtils.toSetOfSpiffeIds(EnvironmentUtils.getProperty(SSL_SPIFFE_ACCEPT_PROPERTY));
    }

    /**
     * Creates a TrustManager initialized with the {@link X509Source} instance
     * that is handled by the {@link X509SourceManager}, and with and a supplier of accepted SPIFFE IDs. that reads
     * the list of {@link SpiffeId} from the System Property 'ssl.spiffe.accept'.
     * <p>
     * If the System property 'ssl.spiffe.acceptAll' is defined as 'true', the TrustManager is configure to accept
     * any SPIFFE ID presented by a peer.
     *
     * @return an instance of a {@link TrustManager} wrapped in an array. The actual type returned is {@link SpiffeTrustManager}
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
     * Creates a TrustManager initialized with the {@link BundleSource} to provide X.509 bundles,
     * and with and a supplier of accepted SPIFFE IDs. that reads the list from the System Property 'ssl.spiffe.accept'.
     * <p>
     * If the System property 'ssl.spiffe.acceptAll' is defined as 'true', the TrustManager is configure to accept
     * any SPIFFE ID presented by a peer.
     *
     * @param x509BundleSource a source of X.509 bundles
     * @return an instance of a {@link TrustManager} wrapped in an array. The actual type returned is {@link SpiffeTrustManager}
     */
    public TrustManager[] engineGetTrustManagers(@NonNull final BundleSource<X509Bundle> x509BundleSource) {
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
     * Creates a {@link TrustManager} initialized with a {@link BundleSource} to provide the X.509 bundles.
     * The TrustManager is configured to accept any SPIFFE ID.
     *
     * @param x509BundleSource a source of X.509 bundles
     * @return an instance of a {@link TrustManager} wrapped in an array. The actual type returned is {@link SpiffeTrustManager}
     */
    public TrustManager[] engineGetTrustManagersAcceptAnySpiffeId(@NonNull final BundleSource<X509Bundle> x509BundleSource) {
        SpiffeTrustManager spiffeTrustManager = new SpiffeTrustManager(x509BundleSource, true);
        return new TrustManager[]{spiffeTrustManager};
    }

    /**
     * Creates a TrustManager initialized with a {@link BundleSource} to provide X.509 bundles,
     * and a supplier of accepted SPIFFE IDs.
     *
     * @param x509BundleSource          a {@link BundleSource} to provide the X.509-Bundles
     * @param acceptedSpiffeIdsSupplier a Supplier to provide a Set of SPIFFE IDs that are accepted
     * @return an instance of a {@link TrustManager} wrapped in an array. The actual type returned is {@link SpiffeTrustManager}
     */
    public TrustManager[] engineGetTrustManagers(
            @NonNull final BundleSource<X509Bundle> x509BundleSource,
            @NonNull final Supplier<Set<SpiffeId>> acceptedSpiffeIdsSupplier) {

        SpiffeTrustManager spiffeTrustManager = new SpiffeTrustManager(x509BundleSource, acceptedSpiffeIdsSupplier);
        return new TrustManager[]{spiffeTrustManager};
    }

    @Override
    protected void engineInit(final KeyStore keyStore) {
        // no implementation needed
    }

    @Override
    protected void engineInit(final ManagerFactoryParameters managerFactoryParameters) {
        // no implementation needed
    }
}
