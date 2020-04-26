package spiffe.exception;

/**
 * Checked exception thrown when there is an error parsing
 * the components of an X509 SVID.
 */
public class X509SvidException extends Exception {

    public X509SvidException(String message) {
        super(message);
    }

    public X509SvidException(String message, Throwable cause) {
        super(message, cause);
    }

    public X509SvidException(Throwable cause) {
        super(cause);
    }
}
