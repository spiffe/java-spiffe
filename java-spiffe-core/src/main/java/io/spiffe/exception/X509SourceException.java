package io.spiffe.exception;

/**
 * Checked thrown when there is an error creating or initializing an X.509 Source.
 */
public class X509SourceException extends Exception {
    public X509SourceException(final String message) {
        super(message);
    }

    public X509SourceException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
