package spiffe.exception;

/**
 * Unchecked exception thrown when a there was an error retrieving
 * or processing a X509Context.
 */
public class X509ContextException extends RuntimeException {
    public X509ContextException(String message) {
        super(message);
    }

    public X509ContextException(String message, Throwable cause) {
        super(message, cause);
    }

    public X509ContextException(Throwable cause) {
        super(cause);
    }
}
