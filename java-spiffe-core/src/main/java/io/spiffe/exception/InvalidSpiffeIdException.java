package io.spiffe.exception;

/**
 * Runtime exception thrown when there is a validation error on
 * a SpiffeId.
 */
public class InvalidSpiffeIdException extends RuntimeException {
    public InvalidSpiffeIdException(String s) {
        super(s);
    }
}
