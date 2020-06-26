package io.spiffe.workloadapi.retry;

import java.time.Duration;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Provides methods to schedule the execution of retries based on a backoff policy.
 */
public class RetryHandler {

    private final ScheduledExecutorService executor;
    private final BackoffPolicy backoffPolicy;
    private Duration nextDelay;

    private int retryCount;

    public RetryHandler(BackoffPolicy backoffPolicy, ScheduledExecutorService executor) {
        this.nextDelay = backoffPolicy.getInitialDelay();
        this.backoffPolicy = backoffPolicy;
        this.executor = executor;
    }

    /**
     * Schedule to execute a Runnable, based on the backoff policy
     * Updates the next delay and retries count.
     *
     * @param runnable the task to be scheduled for execution
     */
    public void scheduleRetry(final Runnable runnable) {
        if (backoffPolicy.didNotReachMaxRetries(retryCount)) {
            executor.schedule(runnable, nextDelay.getSeconds(), TimeUnit.SECONDS);
            nextDelay = backoffPolicy.nextDelay(nextDelay);
            retryCount++;
        }
    }

    /**
     * Reset state of RetryHandle to initial values.
     */
    public void reset() {
        nextDelay = backoffPolicy.getInitialDelay();
        retryCount = 0;
    }

    public Duration getNextDelay() {
        return nextDelay;
    }

    public int getRetryCount() {
        return retryCount;
    }
}
