package io.spiffe.exception;

/**
 * Checked exception thrown when there is an error parsing
 * the components of an X.509 Bundle.
 */
public class X509BundleException extends Exception {
    public X509BundleException(final String message) {
        super(message);
    }

    public X509BundleException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
