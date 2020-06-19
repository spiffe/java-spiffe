package io.spiffe.exception;

/**
 * Checked exception thrown to indicate that an Authority could not be
 * found in the Bundle Source.
 */
public class AuthorityNotFoundException extends Exception {
    public AuthorityNotFoundException(final String message) {
        super(message);
    }

    public AuthorityNotFoundException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
