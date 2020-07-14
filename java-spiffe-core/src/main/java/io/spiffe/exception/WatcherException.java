package io.spiffe.exception;

/**
 * Unchecked exception to be thrown by Watchers onError method.
 */
public class WatcherException extends RuntimeException {
    public WatcherException(String message, Throwable cause) {
        super(message, cause);
    }
}
