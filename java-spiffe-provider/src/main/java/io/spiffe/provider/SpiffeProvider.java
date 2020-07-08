package io.spiffe.provider;

import java.security.Provider;
import java.security.Security;

import static io.spiffe.provider.SpiffeProviderConstants.PROVIDER_NAME;

/**
 * Represents a Security Provider for the Java Security API that supports SPIFFE X.509-SVIDs and Bundles
 * fetched from the Workload API.
 * <p>
 * The  {@link javax.net.ssl.KeyManager} and {@link javax.net.ssl.TrustManager} implementations in this Provider
 * handle the SPIFFE X.509-SVIDs and Bundles in memory fetching them from the Workload API and rotating them automatically.
 * <p>
 * The  {@link io.spiffe.provider.SpiffeKeyManager} provides the X.509-SVID (chain of certificates) to probe identity to another peer
 * in a TLS connection.
 * <p>
 * The {@link io.spiffe.provider.SpiffeTrustManager} provides the X.509 Bundles to validate the peer's X.509 chain of certificates.
 * It also performs SPIFFE ID validation on the SVIDs presented by peers in a TLS connection.
 * <p>
 * The way this Provider is plugged in into the Java Security API is by registering a {@link javax.net.ssl.KeyManagerFactory}
 * for creating an instance of a {@link javax.net.ssl.KeyManager}. It also registers a {@link javax.net.ssl.TrustManagerFactory}
 * for creating an instance of a  {@link javax.net.ssl.TrustManager}.
 * <p>
 * To use this Provider, it is needed to add the following lines to the java.security file:
 * <pre>
 *      security.provider.n=io.spiffe.SpiffeProvider
 *      ssl.KeyManagerFactory.algorithm=Spiffe
 *      ssl.TrustManagerFactory.algorithm=Spiffe
 * </pre>
 * <p>
 * Also, to configure the accepted SPIFFE IDs, add to the java.security the list of SPIFFE IDs
 * separated by the pipe character:
 * <pre>
 *      ssl.spiffe.accept=spiffe://example.org/workload1 | spiffe://example.org/workload2,
 * </pre>
 * This property can also be defined as a System parameter passed through <code>-Dssl.spiffe.accept</code>:
 * <pre>
 *      -Dssl.spiffe.accept=ssl.spiffe.accept=spiffe://example.org/workload1 | spiffe://example.org/workload2
 * </pre>
 * <p>
 * To configure the `TrustManager` to accept any SPIFFE ID presented by a peer,
 * the property <code>ssl.spiffe.acceptAll</code> must be set with the value <code>true</code>:
 * <pre>
 *     ssl.spiffe.acceptAll=true
 * </pre>
 */
public final class SpiffeProvider extends Provider {

    private static final String SPIFFE_KEY_MANAGER_FACTORY =
            String.format("KeyManagerFactory.%s", SpiffeProviderConstants.ALGORITHM);

    private static final String SPIFFE_TRUST_MANAGER_FACTORY =
            String.format("TrustManagerFactory.%s", SpiffeProviderConstants.ALGORITHM);

    private static final String SPIFFE_KEYSTORE = String.format("KeyStore.%s", SpiffeProviderConstants.ALGORITHM);

    /**
     * Constructor.
     * <p>
     * Configure the Provider Name and register KeyManagerFactory, TrustManagerFactory and KeyStore
     */
    public SpiffeProvider() {
        super(PROVIDER_NAME, 0.6, "SPIFFE based KeyStore and TrustStore");
        super.put(SPIFFE_KEY_MANAGER_FACTORY, SpiffeKeyManagerFactory.class.getName());
        super.put(SPIFFE_TRUST_MANAGER_FACTORY, SpiffeTrustManagerFactory.class.getName());
        super.put(SPIFFE_KEYSTORE, SpiffeKeyStore.class.getName());
    }


    /**
     * Installs this provider implementation.
     */
    public static void install() {
        if (Security.getProvider(PROVIDER_NAME) == null) {
            Security.addProvider(new SpiffeProvider());
        }
    }
}
