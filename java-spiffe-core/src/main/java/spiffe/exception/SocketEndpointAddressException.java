package spiffe.exception;

/**
 * Checked exception thrown to indicate that the socket endpoint address
 * could not be parsed or is not valid.
 */
public class SocketEndpointAddressException extends Exception {
    public SocketEndpointAddressException(String message) {
        super(message);
    }

    public SocketEndpointAddressException(String message, Throwable cause) {
        super(message, cause);
    }
}
