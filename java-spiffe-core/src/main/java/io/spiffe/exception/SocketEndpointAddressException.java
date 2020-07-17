package io.spiffe.exception;

/**
 * Checked exception thrown to indicate that the socket endpoint address
 * could not be parsed or is not valid.
 */
public class SocketEndpointAddressException extends Exception {
    public SocketEndpointAddressException(final String message) {
        super(message);
    }

    public SocketEndpointAddressException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
