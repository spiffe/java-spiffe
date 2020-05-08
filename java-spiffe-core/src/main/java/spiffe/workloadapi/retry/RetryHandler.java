package spiffe.workloadapi.retry;

import java.time.Duration;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Provides methods to schedule the execution of retries based on a backoff policy
 */
public class RetryHandler {

    public final ScheduledExecutorService executor;
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
     * Updates the next delay and retries count
     */
    public void scheduleRetry(Runnable runnable) {
        if (backoffPolicy.didNotReachMaxRetries(retryCount)) {
            executor.schedule(runnable, nextDelay.getSeconds(), TimeUnit.SECONDS);
            nextDelay = backoffPolicy.nextDelay(nextDelay);
            retryCount++;
        }
    }

    /**
     * Reset state of RetryHandle to initial values
     */
    public void reset() {
        nextDelay = backoffPolicy.getInitialDelay();
        retryCount = 0;
    }
}
