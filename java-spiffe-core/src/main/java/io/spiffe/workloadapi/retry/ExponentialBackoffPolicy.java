package io.spiffe.workloadapi.retry;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Data;
import lombok.Setter;
import lombok.val;

import java.time.Duration;
import java.util.function.UnaryOperator;

/**
 * Represents a backoff policy for performing retries using exponential increasing delays.
 */
@Data
public class ExponentialBackoffPolicy {

    public static final ExponentialBackoffPolicy DEFAULT = new ExponentialBackoffPolicy();

    // Retry indefinitely, default behavior.
    public static final int UNLIMITED_RETRIES = 0;

    private static final int BACKOFF_MULTIPLIER = 2;

    // The first backoff delay period.
    @Setter(AccessLevel.NONE)
    private Duration initialDelay = Duration.ofSeconds(1);

    // Max time of delay for the backoff period.
    @Setter(AccessLevel.NONE)
    private Duration maxDelay = Duration.ofSeconds(60);

    // Max number of retries, unlimited by default.
    @Setter(AccessLevel.NONE)
    private int maxRetries = UNLIMITED_RETRIES;

    @Setter(AccessLevel.NONE)
    private int backoffMultiplier = BACKOFF_MULTIPLIER;

    @Setter(AccessLevel.NONE)
    private UnaryOperator<Duration> backoffFunction = d -> d.multipliedBy(backoffMultiplier);

    @Builder
    public ExponentialBackoffPolicy(final Duration initialDelay,
                                    final Duration maxDelay,
                                    final int maxRetries,
                                    final int backoffMultiplier) {
        this.initialDelay = initialDelay != null ? initialDelay : Duration.ofSeconds(1);
        this.maxDelay = maxDelay != null ? maxDelay : Duration.ofSeconds(60);
        this.maxRetries = maxRetries != 0 ? maxRetries : UNLIMITED_RETRIES;
        this.backoffMultiplier = backoffMultiplier != 0 ? backoffMultiplier : BACKOFF_MULTIPLIER;
    }

    private ExponentialBackoffPolicy() {
    }

    /**
     * Calculate the nextDelay based on a currentDelay, applying the backoff function
     * If the calculated delay is greater than maxDelay, it returns maxDelay.
     *
     * @param currentDelay a {@link Duration} representing the current delay
     * @return a {@link Duration} representing the next delay
     */
    public Duration nextDelay(final Duration currentDelay) {
        val next = backoffFunction.apply(currentDelay);
        if (next.compareTo(maxDelay) > 0) {
            return maxDelay;
        }
        return next;
    }

    /**
     * Returns false if the RetryPolicy is configured with UNLIMITED_RETRIES
     * or if the retriesCount param is lower than the maxRetries.
     *
     * @param retriesCount the current number of retries
     * @return true if the number of retries reached the max number of retries, false otherwise
     */
    public boolean reachedMaxRetries(final int retriesCount) {
        return maxRetries != UNLIMITED_RETRIES && retriesCount >= maxRetries;
    }
}
