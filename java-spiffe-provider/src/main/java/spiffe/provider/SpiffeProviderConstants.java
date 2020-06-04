package spiffe.provider;

/**
 * SPIFFE Provider constants
 */
public class SpiffeProviderConstants {

    /**
     * Security property to get the list of accepted SPIFFE IDs.
     * This property is read in the java.security file
     */
    public static final String SSL_SPIFFE_ACCEPT_PROPERTY = "ssl.spiffe.accept";

    /**
     * The name of this Provider implementation
     */
    public static final String PROVIDER_NAME = "Spiffe";

    /**
     * The algorithm name for the KeyStore and TrustStore
     */
    public static final String ALGORITHM = "Spiffe";

    /**
     * Alias used by the SpiffeKeyStore.
     * Note: KeyStore aliases are case-insensitive.
     */
    public static final String DEFAULT_ALIAS = "spiffe";

    private SpiffeProviderConstants() {
    }
}
