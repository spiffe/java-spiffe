package spiffe.provider;

import java.security.Provider;
import java.security.Security;

import static spiffe.provider.SpiffeProviderConstants.PROVIDER_NAME;

/**
 * A <code>SpiffeProvider</code> represents a Security Provider for the Java Security API.
 * <p>
 * It uses a custom implementation of KeyStore and TrustStore Managers that support
 * SPIFFE X.509-SVID and Bundle retrieval from the Workload API and SPIFFE ID validation.
 * <p>
 * It registers a KeyManagerFactory for creating a KeyManager that handles an X.509-SVID Certificate to
 * probe identity. It also registers a TrustManagerFactory for creating a TrustManager for trust chain
 * and SPIFFE ID validation.
 * <p>
 *
 * To use this Provider, it is needed to add the following lines to the <tt>java.security</tt> file:
 * <pre>
 * security.provider.<n>=spiffe.provider.SpiffeProvider
 * ssl.KeyManagerFactory.algorithm=Spiffe
 * ssl.TrustManagerFactory.algorithm=Spiffe
 * </pre>
 *
 * Also, to configure the accepted SPIFFE IDs, add to the <tt>java.security</tt> the list of SPIFFE IDs
 * separated by commas:
 * <pre>
 * ssl.spiffe.accept=spiffe://example.org/workload1, spiffe://example.org/workload2, spiffe://other-domain.org/workload
 * </pre>
 */
public final class SpiffeProvider extends Provider {

    private static final String SPIFFE_KEY_MANAGER_FACTORY = String.format("KeyManagerFactory.%s", SpiffeProviderConstants.ALGORITHM);
    private static final String SPIFFE_TRUST_MANAGER_FACTORY = String.format("TrustManagerFactory.%s", SpiffeProviderConstants.ALGORITHM);
    private static final String SPIFFE_KEYSTORE = String.format("KeyStore.%s", SpiffeProviderConstants.ALGORITHM);

    /** Configure the Provider Name and register KeyManagerFactory, TrustManagerFactory and KeyStore */
    public SpiffeProvider() {
        super(PROVIDER_NAME, 0.6, "SPIFFE based KeyStore and TrustStore");
        super.put(SPIFFE_KEY_MANAGER_FACTORY, SpiffeKeyManagerFactory.class.getName());
        super.put(SPIFFE_TRUST_MANAGER_FACTORY, SpiffeTrustManagerFactory.class.getName());
        super.put(SPIFFE_KEYSTORE, SpiffeKeyStore.class.getName());
    }


    /** Install this provider */
    public static void install() {
        if (Security.getProvider(PROVIDER_NAME) == null) {
            Security.addProvider(new SpiffeProvider());
        }
    }
}
