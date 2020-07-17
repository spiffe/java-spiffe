package io.spiffe.exception;

/**
 * Checked exception thrown when a there was an error retrieving
 * or processing an X.509 Context.
 */
public class X509ContextException extends Exception {
    public X509ContextException(final String message) {
        super(message);
    }

    public X509ContextException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
