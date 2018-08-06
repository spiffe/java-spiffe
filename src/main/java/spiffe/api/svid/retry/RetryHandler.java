package spiffe.api.svid.retry;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

/**
 * Handle the retries and backoffs.
 */
public class RetryHandler {

    private long nextDelay;
    private long retryCount;

    private RetryPolicy retryPolicy;
    private ScheduledExecutorService scheduledExecutorService;

    /**
     * Constructor
     * @param retryPolicy
     */
    public RetryHandler(RetryPolicy retryPolicy) {
        this.nextDelay = retryPolicy.initialDelay();
        this.retryPolicy = retryPolicy;
        this.scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();
    }

    /**
     * Schedule to execute a Runnable, based on the retry and backoff policy
     * Updates the next delay and retries count
     * @param callable
     */
    public void scheduleRetry(Runnable callable) {
        if (retryPolicy.checkMaxRetries(retryCount)) {
            scheduledExecutorService.schedule(callable, nextDelay, retryPolicy.timeUnit());
            nextDelay = retryPolicy.nextDelay(nextDelay);
            retryCount++;
        }
    }

    /**
     * Reset state of RetryHandle to initial values
     */
    public void reset() {
        nextDelay = retryPolicy.initialDelay();
        retryCount = 0;
    }
}
