package spiffe.provider;

import java.security.Provider;
import java.security.Security;

import static spiffe.provider.SpiffeProviderConstants.PROVIDER_NAME;

/**
 * This class represents a Security Provider for the Java Security API.
 * It uses a custom implementation of KeyStore and TrustStore Managers that support
 * Spiffe SVID retrieval from the Workload API and Spiffe ID validation
 *
 */
public class SpiffeProvider extends Provider {

    private static final String SPIFFE_KEY_MANAGER_FACTORY = String.format("KeyManagerFactory.%s", SpiffeProviderConstants.ALGORITHM);
    private static final String SPIFFE_TRUST_MANAGER_FACTORY = String.format("TrustManagerFactory.%s", SpiffeProviderConstants.ALGORITHM);
    private static final String SPIFFE_KEYSTORE = String.format("KeyStore.%s", SpiffeProviderConstants.ALGORITHM);

    /**
     * Constructor
     *
     * Configure the Provider Name and register KeyManagerFactory, TrustManagerFactory and KeyStore
     *
     */
    public SpiffeProvider() {
        super(PROVIDER_NAME, 0.1, "SPIFFE based KeyStore and TrustStore");
        super.put(SPIFFE_KEY_MANAGER_FACTORY, SpiffeKeyManagerFactory.class.getName());
        super.put(SPIFFE_TRUST_MANAGER_FACTORY, SpiffeTrustManagerFactory.class.getName());
        super.put(SPIFFE_KEYSTORE, SpiffeKeyStore.class.getName());
    }
}
