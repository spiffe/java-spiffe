package io.spiffe.exception;

/**
 * Checked exception thrown when there is an error creating a JWT Bundle.
 */
public class JwtBundleException extends Exception {
    public JwtBundleException(final String message) {
        super(message);
    }

    public JwtBundleException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
