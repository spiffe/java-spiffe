package spiffe.provider;

/**
 * Unchecked exception thrown when there is an error setting up the source of SVIDs and bundles.
 */
public class SpiffeProviderException extends RuntimeException {

    public SpiffeProviderException(String message) {
        super(message);
    }

    public SpiffeProviderException(String message, Throwable cause) {
        super(message, cause);
    }
}
