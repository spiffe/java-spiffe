package spiffe.provider;

import java.security.Provider;
import java.security.Security;

import static spiffe.provider.SpiffeProviderConstants.PROVIDER_NAME;

/**
 * This class represents a Security Provider" for the Java Security API,
 * It uses a custom implementations of KeyStore and TrustStore Managers that support
 * Spiffe SVID retrieval and SpiffeID validation
 *
 */
public class SpiffeProvider extends Provider {

    /**
     * Constructor
     *
     * Configure the Provider Name and register KeyManagerFactory, TrustManagerFactory and KeyStore
     *
     */
    public SpiffeProvider() {
        super(PROVIDER_NAME, 0.1, "");
        super.put("KeyManagerFactory."+ SpiffeProviderConstants.ALGORITHM, SpiffeKeyManagerFactory.class.getName());
        super.put("TrustManagerFactory." + SpiffeProviderConstants.ALGORITHM, SpiffeTrustManagerFactory.class.getName());
        super.put("KeyStore." + SpiffeProviderConstants.ALGORITHM, SpiffeKeyStore.class.getName());
    }

    public static synchronized void install() {
        Security.setProperty("ssl.KeyManagerFactory.algorithm", SpiffeProviderConstants.ALGORITHM);
        Security.setProperty("ssl.TrustManagerFactory.algorithm", SpiffeProviderConstants.ALGORITHM);

        Security.addProvider(new SpiffeProvider());
    }
}
