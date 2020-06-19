package io.spiffe.workloadapi.retry;

import lombok.Builder;
import lombok.Data;
import lombok.val;

import java.time.Duration;
import java.util.function.UnaryOperator;

/**
 * Represents a backoff policy for performing retries using exponential increasing delays.
 */
@Data
public class BackoffPolicy {

    /**
     * Retry indefinitely, default behavior
     */
    public static final int UNLIMITED_RETRIES = 0;

    private static final int BACKOFF_MULTIPLIER = 2;

    /**
     * The first backoff delay period
     */
    Duration initialDelay = Duration.ofSeconds(1);

    /**
     * Max time of delay for the backoff period
     */
    Duration maxDelay = Duration.ofSeconds(60);

    /**
     * Max number of retries, unlimited by default
     */
    int maxRetries = UNLIMITED_RETRIES;

    /**
     * Function to calculate the backoff delay
     */
    UnaryOperator<Duration> backoffFunction = d -> d.multipliedBy(BACKOFF_MULTIPLIER);

    /**
     * Constructor.
     *
     * Build backoff policy with defaults
     */
    public BackoffPolicy() {
    }

    @Builder
    public BackoffPolicy(Duration initialDelay, Duration maxDelay, int maxRetries, UnaryOperator<Duration> backoffFunction) {
        this.initialDelay = initialDelay != null ? initialDelay : Duration.ofSeconds(1);
        this.maxDelay = maxDelay != null ? maxDelay : Duration.ofSeconds(60);
        this.maxRetries = maxRetries;
        this.backoffFunction = backoffFunction != null ? backoffFunction : d -> d.multipliedBy(BACKOFF_MULTIPLIER);
    }

    /**
     * Calculate the nextDelay based on a currentDelay, applying the backoff function
     * If the calculated delay is greater than maxDelay, it returns maxDelay
     *
     * @param currentDelay a {@link Duration} representing the current delay
     * @return a {@link Duration} representing the next delay
     */
    public Duration nextDelay(Duration currentDelay) {
        val next = backoffFunction.apply(currentDelay);
        if (next.compareTo(maxDelay) > 0) {
            return maxDelay;
        }
        return next;
    }

    /**
     * Returns true if the RetryPolicy is configured with UNLIMITED_RETRIES
     * or if the retriesCount param is lower than the maxRetries
     *
     * @param retriesCount the current number of retries
     * @return false if the number of retries did not reach the max number of retries, true otherwise
     */
    public boolean didNotReachMaxRetries(int retriesCount) {
        return maxRetries == UNLIMITED_RETRIES || retriesCount < maxRetries;
    }
}
