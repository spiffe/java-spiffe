package io.spiffe.exception;

/**
 * Checked thrown when there is an error creating or initializing a JWT Source.
 */
public class JwtSourceException extends Exception {

    public JwtSourceException(final String message) {
        super(message);
    }

    public JwtSourceException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
