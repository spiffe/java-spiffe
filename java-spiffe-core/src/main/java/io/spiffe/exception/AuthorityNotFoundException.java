package io.spiffe.exception;

/**
 * Checked exception thrown to indicate that an Authority could not be
 * found in the Bundle Source.
 */
public class AuthorityNotFoundException extends Exception {
    public AuthorityNotFoundException(String message) {
        super(message);
    }

    public AuthorityNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
