package spiffe.exception;

/**
 * Checked thrown when there is an error creating or initializing a JWT source
 */
public class JwtSourceException extends Exception {

    public JwtSourceException(String message) {
        super(message);
    }

    public JwtSourceException(String message, Throwable cause) {
        super(message, cause);
    }

    public JwtSourceException(Throwable cause) {
        super(cause);
    }
}
