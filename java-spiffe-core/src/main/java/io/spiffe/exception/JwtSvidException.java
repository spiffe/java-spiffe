package io.spiffe.exception;

/**
 * Checked exception thrown when there is an error parsing
 * the components of an JWT SVID.
 */
public class JwtSvidException extends Exception {

    public JwtSvidException(final String message) {
        super(message);
    }

    public JwtSvidException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
