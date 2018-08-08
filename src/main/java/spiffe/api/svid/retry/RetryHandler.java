package spiffe.api.svid.retry;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Handle the retries and backoffs.
 */
public class RetryHandler {

    private static final Logger LOGGER = Logger.getLogger(RetryHandler.class.getName());

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
            LOGGER.log(Level.FINE, String.format("Scheduled Retry no. %s with delay %s ", retryCount, nextDelay));
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
