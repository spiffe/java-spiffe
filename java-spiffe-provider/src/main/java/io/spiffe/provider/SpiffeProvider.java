package io.spiffe.provider;

import java.security.Provider;
import java.security.Security;

import static io.spiffe.provider.SpiffeProviderConstants.PROVIDER_NAME;

/**
 * Represents a Security Provider for the Java Security API.
 * <p>
 * It uses a custom implementation of KeyStore and TrustStore Managers that support
 * SPIFFE X.509-SVID and Bundle retrieval from the Workload API and SPIFFE ID validation.
 * <p>
 * It registers a {@link javax.net.ssl.KeyManagerFactory} for creating a {@link javax.net.ssl.KeyManager}
 * that handles an X.509-SVID Certificate to probe identity. It also registers a {@link javax.net.ssl.TrustManagerFactory}
 * for creating a {@link javax.net.ssl.TrustManager} for trust chain and SPIFFE ID validation.
 * <p>
 * To use this Provider, it is needed to add the following lines to the java.security file:
 * <pre>
 *      security.provider.n=io.spiffe.SpiffeProvider
 *      ssl.KeyManagerFactory.algorithm=Spiffe
 *      ssl.TrustManagerFactory.algorithm=Spiffe
 * </pre>
 * <p>
 * Also, to configure the accepted SPIFFE IDs, add to the java.security the list of SPIFFE IDs
 * separated by commas:
 * <pre>
 *      ssl.spiffe.accept=spiffe://example.org/workload1, spiffe://example.org/workload2, spiffe://other-domain.org/workload
 * </pre>
 * This property can also be defined as a System parameter passed through <code>-Dssl.spiffe.accept</code>:
 * <pre>
 *      -Dssl.spiffe.accept=ssl.spiffe.accept=spiffe://example.org/workload1, spiffe://example.org/workload2
 * </pre>
 * To configure the `TrustManager` to accept any SPIFFE ID presented by a peer, the property <code>ssl.spiffe.acceptAll</code> must be
 * set with the value <code>true</code>:
 * <pre>
 *     ssl.spiffe.acceptAll=true
 * </pre>
 */
public final class SpiffeProvider extends Provider {

    private static final String SPIFFE_KEY_MANAGER_FACTORY = String.format("KeyManagerFactory.%s", SpiffeProviderConstants.ALGORITHM);
    private static final String SPIFFE_TRUST_MANAGER_FACTORY = String.format("TrustManagerFactory.%s", SpiffeProviderConstants.ALGORITHM);
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
