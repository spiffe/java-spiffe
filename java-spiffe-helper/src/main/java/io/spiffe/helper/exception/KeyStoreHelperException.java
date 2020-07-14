package io.spiffe.helper.exception;

/**
 * Checked exception to be thrown when there is an error creating or initializing a KeyStoreHelper.
 */
public class KeyStoreHelperException extends Exception {

    public KeyStoreHelperException(String message) {
        super(message);
    }

    public KeyStoreHelperException(String message, Throwable cause) {
        super(message, cause);
    }
}
