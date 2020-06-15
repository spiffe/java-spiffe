package spiffe.exception;

/**
 * Checked exception thrown when there is an error creating a JWT Bundle.
 */
public class JwtBundleException extends Exception {
    public JwtBundleException(String message) {
        super(message);
    }

    public JwtBundleException(String message, Throwable cause) {
        super(message, cause);
    }
}
