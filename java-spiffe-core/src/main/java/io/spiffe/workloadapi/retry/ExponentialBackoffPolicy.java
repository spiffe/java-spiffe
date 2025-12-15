package io.spiffe.workloadapi.retry;

import java.time.Duration;
import java.util.Objects;
import java.util.function.UnaryOperator;

/**
 * Represents a backoff policy for performing retries using exponential increasing delays.
 */
public class ExponentialBackoffPolicy {

    public static final ExponentialBackoffPolicy DEFAULT = new ExponentialBackoffPolicy();

    // Retry indefinitely, default behavior.
    public static final int UNLIMITED_RETRIES = 0;

    private static final int BACKOFF_MULTIPLIER = 2;

    // The first backoff delay period.
    private Duration initialDelay = Duration.ofSeconds(1);

    // Max time of delay for the backoff period.
    private Duration maxDelay = Duration.ofSeconds(60);

    // Max number of retries, unlimited by default.
    private int maxRetries = UNLIMITED_RETRIES;

    private int backoffMultiplier = BACKOFF_MULTIPLIER;

    private UnaryOperator<Duration> backoffFunction = d -> d.multipliedBy(backoffMultiplier);

    public ExponentialBackoffPolicy(Duration initialDelay,
                                    Duration maxDelay,
                                    int maxRetries,
                                    int backoffMultiplier) {

        this.initialDelay = initialDelay != null ? initialDelay : Duration.ofSeconds(1);
        this.maxDelay = maxDelay != null ? maxDelay : Duration.ofSeconds(60);
        this.maxRetries = maxRetries != 0 ? maxRetries : UNLIMITED_RETRIES;
        this.backoffMultiplier = backoffMultiplier != 0 ? backoffMultiplier : BACKOFF_MULTIPLIER;
        this.backoffFunction = d -> d.multipliedBy(this.backoffMultiplier);
    }

    private ExponentialBackoffPolicy() {
    }

    public Duration getInitialDelay() {
        return initialDelay;
    }

    public Duration getMaxDelay() {
        return maxDelay;
    }

    public int getMaxRetries() {
        return maxRetries;
    }

    public int getBackoffMultiplier() {
        return backoffMultiplier;
    }

    public UnaryOperator<Duration> getBackoffFunction() {
        return backoffFunction;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private Duration initialDelay;
        private Duration maxDelay;
        private int maxRetries;
        private int backoffMultiplier;

        public Builder initialDelay(Duration initialDelay) {
            this.initialDelay = initialDelay;
            return this;
        }

        public Builder maxDelay(Duration maxDelay) {
            this.maxDelay = maxDelay;
            return this;
        }

        public Builder maxRetries(int maxRetries) {
            this.maxRetries = maxRetries;
            return this;
        }

        public Builder backoffMultiplier(int backoffMultiplier) {
            this.backoffMultiplier = backoffMultiplier;
            return this;
        }

        public ExponentialBackoffPolicy build() {
            return new ExponentialBackoffPolicy(
                    initialDelay,
                    maxDelay,
                    maxRetries,
                    backoffMultiplier
            );
        }
    }

    /**
     * Calculate the nextDelay based on a currentDelay, applying the backoff function
     * If the calculated delay is greater than maxDelay, it returns maxDelay.
     *
     * @param currentDelay a {@link Duration} representing the current delay
     * @return a {@link Duration} representing the next delay
     */
    public Duration nextDelay(final Duration currentDelay) {
        // current delay didn't exceed maxDelay already
        if (currentDelay.compareTo(maxDelay) < 0) {
            return calculateNextDelay(currentDelay);
        }
        return maxDelay;
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

    private Duration calculateNextDelay(final Duration currentDelay) {
        Duration next = backoffFunction.apply(currentDelay);
        if (next.compareTo(maxDelay) > 0) {
            return maxDelay;
        }
        return next;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ExponentialBackoffPolicy)) return false;
        ExponentialBackoffPolicy that = (ExponentialBackoffPolicy) o;
        return maxRetries == that.maxRetries &&
                backoffMultiplier == that.backoffMultiplier &&
                Objects.equals(initialDelay, that.initialDelay) &&
                Objects.equals(maxDelay, that.maxDelay) &&
                Objects.equals(backoffFunction, that.backoffFunction);
    }

    @Override
    public int hashCode() {
        return Objects.hash(initialDelay, maxDelay, maxRetries, backoffMultiplier, backoffFunction);
    }

    @Override
    public String toString() {
        return "ExponentialBackoffPolicy(" +
                "initialDelay=" + initialDelay +
                ", maxDelay=" + maxDelay +
                ", maxRetries=" + maxRetries +
                ", backoffMultiplier=" + backoffMultiplier +
                ", backoffFunction=" + backoffFunction +
                ')';
    }
}
