package spiffe.api.svid.util;

import io.grpc.StatusRuntimeException;

import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;

/**
 * Implements a basic Exponential Backoff Policy
 * Retries based on a List of Errors
 *
 */
public class ExponentialBackOff {

    static int MAX_RETRIES = 5;
    static int BASE = 2;

    /**
     * The list of Errors that can produce the WorkloadApi and must cause a Retry
     */
    private static List<String> RETRYABLE_ERRORS = Arrays.asList("UNAVAILABLE", "PERMISSIONDENIED");

    private ExponentialBackOff() {
    }

    /**
     * Execute a Function given as parameter
     * @param fn The Function to execute
     * @param <T>
     * @return
     */
    public static <T> T execute(Supplier<T> fn) {
        for (int attempt = 1; attempt < MAX_RETRIES; attempt++) {
            try {
                return fn.get();
            } catch (StatusRuntimeException e) {
                handleError(e, attempt);
            }
        }
        throw new RuntimeException("Failed to communicate with the Workload API");
    }

    private static void handleError(StatusRuntimeException e, int attempt) {
        if (isRetryableError(e)) {
            sleep(backoffSequenceGenerator(attempt));
        } else {
            throw new RuntimeException("Not retryable error occurred. ", e);
        }
    }

    private static boolean isRetryableError(StatusRuntimeException e) {
        return RETRYABLE_ERRORS.contains(e.getStatus().getCode().name());
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    private static long backoffSequenceGenerator(int attempt) {
        return (long) Math.pow(BASE, attempt) * 1000;
    }
}
