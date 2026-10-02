package io.spiffe.workloadapi.retry;

import java.time.Duration;
import java.util.concurrent.RejectedExecutionException;
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
     * Updates the next delay and retries count if the retry is scheduled.
     * <p>
     * This method does not report whether the retry was scheduled. Use {@link #tryScheduleRetry(Runnable)}
     * to detect retries that could not be scheduled.
     *
     * @param runnable the task to be scheduled for execution
     */
    public void scheduleRetry(final Runnable runnable) {
        tryScheduleRetry(runnable);
    }

    /**
     * Attempts to schedule the execution of a Runnable, based on the backoff policy.
     * Updates the next delay and retries count only if the retry is scheduled.
     *
     * @param runnable the task to be scheduled for execution
     * @return true if the retry was scheduled; false if the executor is shut down, the maximum number of
     * retries has been reached, or the executor rejected the task
     */
    public boolean tryScheduleRetry(final Runnable runnable) {
        if (executor.isShutdown()) {
            return false;
        }

        if (exponentialBackoffPolicy.reachedMaxRetries(retryCount)) {
            return false;
        }

        try {
            executor.schedule(runnable, nextDelay.toMillis(), TimeUnit.MILLISECONDS);
        } catch (RejectedExecutionException e) {
            return false;
        }

        nextDelay = exponentialBackoffPolicy.nextDelay(nextDelay);
        retryCount++;
        return true;
    }

    /**
     * Returns true is a new retry should be performs, according the the Retry Policy.
     * @return true is a new retry should be performs, according the the Retry Policy
     */
    public boolean shouldRetry() {
        return !exponentialBackoffPolicy.reachedMaxRetries(retryCount);
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
