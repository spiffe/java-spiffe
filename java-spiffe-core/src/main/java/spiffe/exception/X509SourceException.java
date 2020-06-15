package spiffe.exception;

/**
 * Checked thrown when there is an error creating or initializing a X.509 Source.
 */
public class X509SourceException extends Exception {
    public X509SourceException(String message) {
        super(message);
    }

    public X509SourceException(String message, Throwable cause) {
        super(message, cause);
    }
}
