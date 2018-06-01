package spiffe.api.svid.retry;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

/**
 * Handle the retries and backoffs.
 */
public class RetryHandler {

    private long nextDelay;

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
     * Schedule to execture a Runnable, based on the retry and backoff policy
     * Updates the next delay
     * @param callable
     */
    public void scheduleRetry(Runnable callable) {
        scheduledExecutorService.schedule(callable, nextDelay, retryPolicy.timeUnit());
        nextDelay = retryPolicy.nextDelay(nextDelay);
    }
}
