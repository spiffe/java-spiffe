package io.spiffe.helper.exception;

/**
 * Checked exception to be thrown when there are errors configuring the cli Runner.
 */
public class RunnerException extends Exception {
    public RunnerException(String message) {
        super(message);
    }

    public RunnerException(Throwable cause) {
        super(cause);
    }

    public RunnerException(String message, Throwable cause) {
        super(message, cause);
    }
}
