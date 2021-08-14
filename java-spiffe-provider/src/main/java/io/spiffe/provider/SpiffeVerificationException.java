package io.spiffe.provider;

/**
 * This class indicates there was a problem verifying a peer's SPIFFE ID. The message should be used to indicate what
 * issue was encountered.
 */
public class SpiffeVerificationException extends Exception {
    public SpiffeVerificationException(String message) {
        super(message);
    }
}
