package io.spiffe.workloadapi.retry;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import java.time.Duration;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

class RetryHandlerTest {

    @Mock
    ScheduledExecutorService scheduledExecutorService;

    @BeforeEach
    void setup() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    void testScheduleRetry_defaultPolicy() {
        Runnable runnable = () -> { };
        ExponentialBackoffPolicy exponentialBackoffPolicy = ExponentialBackoffPolicy.DEFAULT;

        RetryHandler retryHandler = new RetryHandler(exponentialBackoffPolicy, scheduledExecutorService);

        retryHandler.scheduleRetry(runnable);

        verify(scheduledExecutorService).schedule(runnable, 1, TimeUnit.SECONDS);
        assertEquals(1, retryHandler.getRetryCount());

        // second retry
        retryHandler.scheduleRetry(runnable);
        assertEquals(2, retryHandler.getRetryCount());
        verify(scheduledExecutorService).schedule(runnable, 2, TimeUnit.SECONDS);

        // third retry
        retryHandler.scheduleRetry(runnable);
        assertEquals(3, retryHandler.getRetryCount());
        verify(scheduledExecutorService).schedule(runnable, 4, TimeUnit.SECONDS);

        // fourth retry
        retryHandler.scheduleRetry(runnable);
        assertEquals(4, retryHandler.getRetryCount());
        verify(scheduledExecutorService).schedule(runnable, 8, TimeUnit.SECONDS);
    }

    @Test
    void testScheduleRetry_maxRetries() {
        Runnable runnable = () -> { };
        ExponentialBackoffPolicy exponentialBackoffPolicy = ExponentialBackoffPolicy.builder().maxRetries(3).build();

        RetryHandler retryHandler = new RetryHandler(exponentialBackoffPolicy, scheduledExecutorService);

        retryHandler.scheduleRetry(runnable);

        verify(scheduledExecutorService).schedule(runnable, 1, TimeUnit.SECONDS);
        assertEquals(1, retryHandler.getRetryCount());

        // second retry
        retryHandler.scheduleRetry(runnable);
        assertEquals(2, retryHandler.getRetryCount());
        verify(scheduledExecutorService).schedule(runnable, 2, TimeUnit.SECONDS);

        // third retry
        retryHandler.scheduleRetry(runnable);
        assertEquals(3, retryHandler.getRetryCount());
        verify(scheduledExecutorService).schedule(runnable, 4, TimeUnit.SECONDS);

        Mockito.reset(scheduledExecutorService);

        // fourth retry exceeds max retries
        retryHandler.scheduleRetry(runnable);
        verify(scheduledExecutorService).isShutdown();
        verifyNoMoreInteractions(scheduledExecutorService);
    }

    @Test
    void testReset() {
        ExponentialBackoffPolicy exponentialBackoffPolicy = ExponentialBackoffPolicy.builder().initialDelay(Duration.ofSeconds(20)).build();

        RetryHandler retryHandler = new RetryHandler(exponentialBackoffPolicy, scheduledExecutorService);

        // check initial delay
        assertEquals(Duration.ofSeconds(20), retryHandler.getNextDelay());

        // schedule a retry
        retryHandler.scheduleRetry(() -> {});

        // check that the next delay was updated
        assertEquals(Duration.ofSeconds(40), retryHandler.getNextDelay());

        // reset the retry handler
        retryHandler.reset();

        // check that the nextDelay was reset to initialDelay
        assertEquals(Duration.ofSeconds(20), retryHandler.getNextDelay());
    }

}