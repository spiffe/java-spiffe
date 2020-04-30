package spiffe.provider;

/**
 * Constants to be used in the context of the SPIFFE Provider
 */
class SpiffeProviderConstants {

    /**
     * Security property to get the list of accepted SPIFFE IDs.
     * This property is read in the java.security file
     */
    static final String SSL_SPIFFE_ACCEPT_PROPERTY = "ssl.spiffe.accept";

    // the name of this Provider implementation
    static final String PROVIDER_NAME = "Spiffe";

    // the algorithm name for the KeyStore and TrustStore
    static final String ALGORITHM = "Spiffe";

    // alias used by the SpiffeKeyStore
    static final String DEFAULT_ALIAS = "Spiffe";

    private SpiffeProviderConstants() {}
}
