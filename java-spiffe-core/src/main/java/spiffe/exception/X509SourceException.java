package spiffe.exception;

/**
 * Unchecked thrown when there is an error creating or initializing a X509 source
 */
public class X509SourceException extends RuntimeException {
    public X509SourceException(String message) {
        super(message);
    }

    public X509SourceException(String message, Throwable cause) {
        super(message, cause);
    }

    public X509SourceException(Throwable cause) {
        super(cause);
    }
}
