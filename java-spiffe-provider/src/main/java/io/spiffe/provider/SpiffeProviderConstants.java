package io.spiffe.provider;

/**
 * SPIFFE Provider constants.
 */
public final class SpiffeProviderConstants {

    /**
     * Name of the property to get the Set of accepted SPIFFE IDs.
     * This property is read in the java.security file or from a System property.
     */
    public static final String SSL_SPIFFE_ACCEPT_PROPERTY = "ssl.spiffe.accept";

    /**
     * Name of the property to be used as flag for accepting any SPIFFE IDs.
     * This property is read from the java.security file or from the System.
     */
    public static final String SSL_SPIFFE_ACCEPT_ALL_PROPERTY = "ssl.spiffe.acceptAll";

    /**
     * The name of this Provider implementation.
     */
    public static final String PROVIDER_NAME = "Spiffe";

    /**
     * The algorithm name for the KeyStore and TrustStore.
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
