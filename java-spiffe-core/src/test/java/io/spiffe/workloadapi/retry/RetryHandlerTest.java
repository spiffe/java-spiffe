package io.spiffe.workloadapi.retry;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import java.time.Duration;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

class RetryHandlerTest {

    @Mock
    ScheduledExecutorService scheduledExecutorService;

    private AutoCloseable mocks;

    @BeforeEach
    void setup() {
        mocks = MockitoAnnotations.openMocks(this);
    }

    @AfterEach
    void tearDown() throws Exception {
        mocks.close();
    }

    @Test
    void testTryScheduleRetry_defaultPolicy() {
        Runnable runnable = () -> { };
        ExponentialBackoffPolicy exponentialBackoffPolicy = ExponentialBackoffPolicy.DEFAULT;

        RetryHandler retryHandler = new RetryHandler(exponentialBackoffPolicy, scheduledExecutorService);

        assertTrue(retryHandler.tryScheduleRetry(runnable));

        verify(scheduledExecutorService).schedule(runnable, 1000, TimeUnit.MILLISECONDS);
        assertEquals(1, retryHandler.getRetryCount());

        // second retry
        assertTrue(retryHandler.tryScheduleRetry(runnable));
        assertEquals(2, retryHandler.getRetryCount());
        verify(scheduledExecutorService).schedule(runnable, 2000, TimeUnit.MILLISECONDS);

        // third retry
        assertTrue(retryHandler.tryScheduleRetry(runnable));
        assertEquals(3, retryHandler.getRetryCount());
        verify(scheduledExecutorService).schedule(runnable, 4000, TimeUnit.MILLISECONDS);

        // fourth retry
        assertTrue(retryHandler.tryScheduleRetry(runnable));
        assertEquals(4, retryHandler.getRetryCount());
        verify(scheduledExecutorService).schedule(runnable, 8000, TimeUnit.MILLISECONDS);
    }

    @Test
    void testScheduleRetry_legacyVoidMethod_schedulesRetry() {
        Runnable runnable = () -> { };
        ExponentialBackoffPolicy exponentialBackoffPolicy = ExponentialBackoffPolicy.DEFAULT;

        RetryHandler retryHandler = new RetryHandler(exponentialBackoffPolicy, scheduledExecutorService);

        retryHandler.scheduleRetry(runnable);

        verify(scheduledExecutorService).schedule(runnable, 1000, TimeUnit.MILLISECONDS);
        assertEquals(1, retryHandler.getRetryCount());
        assertEquals(Duration.ofSeconds(2), retryHandler.getNextDelay());
    }

    @Test
    void testScheduleRetry_subSecondDelay_usesMilliseconds() {
        Runnable runnable = () -> { };
        ExponentialBackoffPolicy exponentialBackoffPolicy = ExponentialBackoffPolicy.builder()
                .initialDelay(Duration.ofMillis(250))
                .build();

        RetryHandler retryHandler = new RetryHandler(exponentialBackoffPolicy, scheduledExecutorService);

        retryHandler.scheduleRetry(runnable);

        verify(scheduledExecutorService).schedule(runnable, 250, TimeUnit.MILLISECONDS);
        assertEquals(1, retryHandler.getRetryCount());
    }

    @Test
    void testTryScheduleRetry_maxRetries() {
        Runnable runnable = () -> { };
        ExponentialBackoffPolicy exponentialBackoffPolicy = ExponentialBackoffPolicy.builder().maxRetries(3).build();

        RetryHandler retryHandler = new RetryHandler(exponentialBackoffPolicy, scheduledExecutorService);

        assertTrue(retryHandler.tryScheduleRetry(runnable));

        verify(scheduledExecutorService).schedule(runnable, 1000, TimeUnit.MILLISECONDS);
        assertEquals(1, retryHandler.getRetryCount());

        // second retry
        assertTrue(retryHandler.tryScheduleRetry(runnable));
        assertEquals(2, retryHandler.getRetryCount());
        verify(scheduledExecutorService).schedule(runnable, 2000, TimeUnit.MILLISECONDS);

        // third retry
        assertTrue(retryHandler.tryScheduleRetry(runnable));
        assertEquals(3, retryHandler.getRetryCount());
        verify(scheduledExecutorService).schedule(runnable, 4000, TimeUnit.MILLISECONDS);

        Mockito.reset(scheduledExecutorService);

        // fourth retry exceeds max retries
        assertFalse(retryHandler.tryScheduleRetry(runnable));
        verify(scheduledExecutorService).isShutdown();
        verifyNoMoreInteractions(scheduledExecutorService);
        assertEquals(3, retryHandler.getRetryCount());
        assertEquals(Duration.ofSeconds(8), retryHandler.getNextDelay());
    }

    @Test
    void testTryScheduleRetry_executorShutdown() {
        Runnable runnable = () -> { };
        ExponentialBackoffPolicy exponentialBackoffPolicy = ExponentialBackoffPolicy.DEFAULT;
        when(scheduledExecutorService.isShutdown()).thenReturn(true);

        RetryHandler retryHandler = new RetryHandler(exponentialBackoffPolicy, scheduledExecutorService);

        assertFalse(retryHandler.tryScheduleRetry(runnable));
        verify(scheduledExecutorService).isShutdown();
        verifyNoMoreInteractions(scheduledExecutorService);
        assertEquals(0, retryHandler.getRetryCount());
        assertEquals(Duration.ofSeconds(1), retryHandler.getNextDelay());
    }

    @Test
    void testTryScheduleRetry_rejectedExecution_leavesStateUnchanged() {
        Runnable runnable = () -> { };
        ExponentialBackoffPolicy exponentialBackoffPolicy = ExponentialBackoffPolicy.DEFAULT;
        when(scheduledExecutorService.schedule(any(Runnable.class), anyLong(), any(TimeUnit.class)))
                .thenThrow(new RejectedExecutionException("rejected"));

        RetryHandler retryHandler = new RetryHandler(exponentialBackoffPolicy, scheduledExecutorService);

        assertFalse(retryHandler.tryScheduleRetry(runnable));
        verify(scheduledExecutorService).schedule(runnable, 1000, TimeUnit.MILLISECONDS);
        assertEquals(0, retryHandler.getRetryCount());
        assertEquals(Duration.ofSeconds(1), retryHandler.getNextDelay());
    }

    @Test
    void testScheduleRetry_legacyVoidMethod_rejectedExecution_leavesStateUnchanged() {
        Runnable runnable = () -> { };
        ExponentialBackoffPolicy exponentialBackoffPolicy = ExponentialBackoffPolicy.DEFAULT;
        when(scheduledExecutorService.schedule(any(Runnable.class), anyLong(), any(TimeUnit.class)))
                .thenThrow(new RejectedExecutionException("rejected"));

        RetryHandler retryHandler = new RetryHandler(exponentialBackoffPolicy, scheduledExecutorService);

        retryHandler.scheduleRetry(runnable);

        verify(scheduledExecutorService).schedule(runnable, 1000, TimeUnit.MILLISECONDS);
        assertEquals(0, retryHandler.getRetryCount());
        assertEquals(Duration.ofSeconds(1), retryHandler.getNextDelay());
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
