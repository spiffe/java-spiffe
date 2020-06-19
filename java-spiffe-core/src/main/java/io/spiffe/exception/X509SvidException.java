package io.spiffe.exception;

/**
 * Checked exception thrown when there is an error parsing
 * the components of an X.509 SVID.
 */
public class X509SvidException extends Exception {
    public X509SvidException(final String message) {
        super(message);
    }

    public X509SvidException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
