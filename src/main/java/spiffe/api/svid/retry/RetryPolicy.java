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
    private TimeUnit timeUnit;
    private Function<Long, Long> backoffFunction;

    /**
     * Constructor
     *
     * Sets default backoff function to multiply by 2
     * @param initialDelay
     * @param maxDelay
     * @param timeUnit
     */
    public RetryPolicy(long initialDelay, long maxDelay, TimeUnit timeUnit) {
        if (initialDelay < 1) {
            this.initialDelay = 1;
        } else {
            this.initialDelay = initialDelay;
        }
        this.maxDelay = maxDelay;
        this.timeUnit = timeUnit;
        this.backoffFunction = (d) -> d * 2;

    }

    /**
     * Constructor
     *
     * Allow to configure the backoff function
     * @param initialDelay
     * @param maxDelay
     * @param timeUnit
     * @param backoffFunction
     */
    public RetryPolicy(long initialDelay, long maxDelay, TimeUnit timeUnit, Function<Long, Long> backoffFunction) {
        this.initialDelay = initialDelay;
        this.maxDelay = maxDelay;
        this.timeUnit = timeUnit;
        this.backoffFunction = backoffFunction;
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
}
