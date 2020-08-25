package io.spiffe.provider;

import io.spiffe.bundle.BundleSource;
import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.exception.X509SourceException;
import io.spiffe.provider.exception.SpiffeProviderException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.SpiffeIdUtils;
import io.spiffe.workloadapi.DefaultX509Source;
import io.spiffe.workloadapi.X509Source;
import lombok.NonNull;
import lombok.val;

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
 * {@link DefaultX509Source} that is maintained via the Workload API.
 * <p>
 * The Java Security API will call <code>engineGetTrustManagers()</code> to get an instance of a {@link TrustManager}.
 * This TrustManager instance gets injected an {@link DefaultX509Source}, which implements {@link BundleSource} and
 * keeps bundles updated.
 * The TrustManager also gets a Supplier of a Set of accepted SPIFFE IDs used to validate the SPIFFE ID from the SVIDs
 * presented by a peer during the secure socket handshake.
 *
 * @see SpiffeSslContextFactory
 * @see BundleSource
 * @see SpiffeSslContextFactory
 */
public class SpiffeTrustManagerFactory extends TrustManagerFactorySpi {

    private static final boolean ACCEPT_ANY_SPIFFE_ID =
            Boolean.parseBoolean(EnvironmentUtils.getProperty(SSL_SPIFFE_ACCEPT_ALL_PROPERTY, "false"));

    private static final Supplier<Set<SpiffeId>> DEFAULT_SPIFFE_ID_SET_SUPPLIER =
            () -> SpiffeIdUtils.toSetOfSpiffeIds(EnvironmentUtils.getProperty(SSL_SPIFFE_ACCEPT_PROPERTY));

    /**
     * Creates a {@link TrustManager} initialized with the {@link DefaultX509Source} instance
     * that is handled by the {@link X509SourceManager}, and with and a supplier of accepted SPIFFE IDs. that reads
     * the Set of {@link SpiffeId} from the System Property 'ssl.spiffe.accept'.
     * <p>
     * If the System property 'ssl.spiffe.acceptAll' is defined as 'true', the TrustManager is configure to accept
     * any SPIFFE ID presented by a peer.
     *
     * @return an instance of a {@link TrustManager} wrapped in an array. The actual type returned
     * is {@link SpiffeTrustManager}
     * @throws SpiffeProviderException in case there is an error setting up the X.509 source
     */
    @Override
    public TrustManager[] engineGetTrustManagers() {

        final X509Source x509Source;
        try {
            x509Source = X509SourceManager.getX509Source();
        } catch (X509SourceException e) {
            throw new SpiffeProviderException("The X.509 source could not be created", e);
        } catch (SocketEndpointAddressException e) {
            throw new SpiffeProviderException("The Workload API Socket endpoint address configured is not valid", e);
        }

        final SpiffeTrustManager spiffeTrustManager;
        if (ACCEPT_ANY_SPIFFE_ID) {
            spiffeTrustManager = new SpiffeTrustManager(x509Source);
        } else {
            spiffeTrustManager = new SpiffeTrustManager(x509Source, DEFAULT_SPIFFE_ID_SET_SUPPLIER);
        }
        return new TrustManager[]{spiffeTrustManager};
    }

    /**
     * Creates a {@link TrustManager} initialized with the {@link BundleSource} to provide X.509 bundles,
     * and with and a supplier of accepted SPIFFE IDs. that reads the set from the System Property 'ssl.spiffe.accept'.
     * <p>
     * If the System property 'ssl.spiffe.acceptAll' is defined as 'true', the TrustManager is configure to accept
     * any SPIFFE ID presented by a peer.
     *
     * @param x509BundleSource a source of X.509 bundles
     * @return an instance of a {@link TrustManager} wrapped in an array. The actual type returned
     * is {@link SpiffeTrustManager}
     */
    public TrustManager[] engineGetTrustManagers(@NonNull final BundleSource<X509Bundle> x509BundleSource) {
        final SpiffeTrustManager spiffeTrustManager;

        if (ACCEPT_ANY_SPIFFE_ID) {
            spiffeTrustManager = new SpiffeTrustManager(x509BundleSource);
        } else {
            spiffeTrustManager = new SpiffeTrustManager(x509BundleSource, DEFAULT_SPIFFE_ID_SET_SUPPLIER);
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
        val spiffeTrustManager = new SpiffeTrustManager(x509BundleSource);
        return new TrustManager[]{spiffeTrustManager};
    }

    /**
     * Creates a TrustManager initialized with a {@link BundleSource} to provide X.509 bundles,
     * and a supplier of accepted SPIFFE IDs.
     *
     * @param x509BundleSource          a {@link BundleSource} to provide the X.509-Bundles
     * @param acceptedSpiffeIdsSupplier a Supplier to provide a set of SPIFFE IDs that are accepted
     * @return an instance of a {@link TrustManager} wrapped in an array. The actual type returned is {@link SpiffeTrustManager}
     */
    public TrustManager[] engineGetTrustManagers(
            @NonNull final BundleSource<X509Bundle> x509BundleSource,
            @NonNull final Supplier<Set<SpiffeId>> acceptedSpiffeIdsSupplier) {

        val spiffeTrustManager = new SpiffeTrustManager(x509BundleSource, acceptedSpiffeIdsSupplier);
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
