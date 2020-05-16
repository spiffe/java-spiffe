package spiffe.exception;

/**
 * Checked exception thrown to indicate that an authority could not be
 * found in the bundle source.
 */
public class AuthorityNotFoundException extends Exception {
    public AuthorityNotFoundException(String message) {
        super(message);
    }

    public AuthorityNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
