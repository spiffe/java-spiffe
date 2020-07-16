package io.spiffe.provider.exception;

/**
 * Unchecked exception thrown when there is an error setting up the source of SVIDs and bundles.
 */
public class SpiffeProviderException extends RuntimeException {

    public SpiffeProviderException(final String message) {
        super(message);
    }

    public SpiffeProviderException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
