package spiffe.exception;

/**
 * Checked exception thrown when there is an error parsing
 * the components of an JWT SVID.
 */
public class JwtSvidException extends Exception {

    public JwtSvidException(String message) {
        super(message);
    }

    public JwtSvidException(String message, Throwable cause) {
        super(message, cause);
    }

    public JwtSvidException(Throwable cause) {
        super(cause);
    }
}
