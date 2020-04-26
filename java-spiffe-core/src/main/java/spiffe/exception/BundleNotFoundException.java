package spiffe.exception;

/**
 * Checked exception thrown to indicate that a bundle could not be
 * found in the bundle source.
 */
public class BundleNotFoundException extends Exception {
    public BundleNotFoundException(String message) {
        super(message);
    }

    public BundleNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
