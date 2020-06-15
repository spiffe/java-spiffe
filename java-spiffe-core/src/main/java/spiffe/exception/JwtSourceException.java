package spiffe.exception;

/**
 * Checked thrown when there is an error creating or initializing a JWT Source.
 */
public class JwtSourceException extends Exception {

    public JwtSourceException(String message) {
        super(message);
    }

    public JwtSourceException(String message, Throwable cause) {
        super(message, cause);
    }
}
