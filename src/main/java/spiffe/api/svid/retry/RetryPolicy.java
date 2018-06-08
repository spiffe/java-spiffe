package spiffe.api.svid.retry;

import java.util.concurrent.TimeUnit;
import java.util.function.Function;

/**
 * Configuration Parameters for the Retry behavior
 * Allow configure initialDelay, maxDelay, timeUnit
 * and the Function to calculate the delays
 */
public class RetryPolicy {

    private long initialDelay;
    private long maxDelay;
    private long maxRetries;
    private TimeUnit timeUnit;
    private Function<Long, Long> backoffFunction;

    private final static long UNLIMITED_RETRIES = 0;

    /**
     * Default Constructor
     *
     */
    public RetryPolicy() {
        this.initialDelay = 1;
        this.maxDelay = 300;
        this.timeUnit = TimeUnit.SECONDS;
        this.backoffFunction = (d) -> d * 2;
        this.maxRetries = UNLIMITED_RETRIES;
    }

    public long initialDelay() {
        return initialDelay;
    }

    public TimeUnit timeUnit() {
        return timeUnit;
    }

    /**
     * Calculate the nextDelay based on a currentDelay, applying the backoff function
     * If the calculated delay is greater than maxDelay, it returns maxDelay
     * @param currentDelay
     * @return
     */
    public long nextDelay(long currentDelay) {
        long next = backoffFunction.apply(currentDelay);
        return next < maxDelay ? next : maxDelay;
    }

    /**
     * Returns true if the RetryPolicy is configure with UNLIMITED_RETRIES
     * or if the retries param is lower than the maxRetries
     *
     * @param retries
     * @return
     */
    public boolean checkMaxRetries(long retries) {
        return maxRetries == UNLIMITED_RETRIES || retries < maxRetries;
    }

    public void setInitialDelay(long initialDelay) {
        this.initialDelay = initialDelay;
    }

    public void setMaxDelay(long maxDelay) {
        this.maxDelay = maxDelay;
    }

    public void setMaxRetries(long maxRetries) {
        this.maxRetries = maxRetries;
    }

    public void setTimeUnit(TimeUnit timeUnit) {
        this.timeUnit = timeUnit;
    }

    public void setBackoffFunction(Function<Long, Long> backoffFunction) {
        this.backoffFunction = backoffFunction;
    }
}
