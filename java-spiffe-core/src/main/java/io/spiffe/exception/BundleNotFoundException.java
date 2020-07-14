package io.spiffe.exception;

/**
 * Checked exception thrown to indicate that a Bundle could not be
 * found in the Bundle Source.
 */
public class BundleNotFoundException extends Exception {
    public BundleNotFoundException(final String message) {
        super(message);
    }
}
