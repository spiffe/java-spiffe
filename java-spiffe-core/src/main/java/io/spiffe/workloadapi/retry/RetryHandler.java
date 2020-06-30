package io.spiffe.workloadapi.retry;

import java.time.Duration;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Provides methods to schedule the execution of retries based on a backoff policy.
 */
public class RetryHandler {

    private final ScheduledExecutorService executor;
    private final ExponentialBackoffPolicy exponentialBackoffPolicy;
    private Duration nextDelay;

    private int retryCount;

    public RetryHandler(final ExponentialBackoffPolicy exponentialBackoffPolicy, final ScheduledExecutorService executor) {
        this.nextDelay = exponentialBackoffPolicy.getInitialDelay();
        this.exponentialBackoffPolicy = exponentialBackoffPolicy;
        this.executor = executor;
    }

    /**
     * Schedule to execute a Runnable, based on the backoff policy
     * Updates the next delay and retries count.
     *
     * @param runnable the task to be scheduled for execution
     */
    public void scheduleRetry(final Runnable runnable) {
        if (exponentialBackoffPolicy.reachedMaxRetries(retryCount)) {
            return;
        }
        executor.schedule(runnable, nextDelay.getSeconds(), TimeUnit.SECONDS);
        nextDelay = exponentialBackoffPolicy.nextDelay(nextDelay);
        retryCount++;
    }

    /**
     * Reset state of RetryHandle to initial values.
     */
    public void reset() {
        nextDelay = exponentialBackoffPolicy.getInitialDelay();
        retryCount = 0;
    }

    public Duration getNextDelay() {
        return nextDelay;
    }

    public int getRetryCount() {
        return retryCount;
    }
}
