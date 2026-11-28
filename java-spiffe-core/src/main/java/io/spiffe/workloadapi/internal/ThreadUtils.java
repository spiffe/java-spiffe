package io.spiffe.workloadapi.internal;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public final class ThreadUtils {

    private ThreadUtils() {
    }

    /**
     * Waits until the latch has counted down to zero, or until the timeout elapses. A zero timeout waits without a
     * deadline. The timeout is not rounded, so sub-second timeouts are honored. A timeout too long to be represented
     * in nanoseconds (about 292 years) is capped to that.
     *
     * @param latch   the latch to wait for
     * @param timeout the maximum time to wait, or zero to wait without a deadline
     * @return {@code true} if the count reached zero, {@code false} if the timeout elapsed first
     * @throws InterruptedException if the current thread is interrupted while waiting
     */
    public static boolean await(final CountDownLatch latch, final Duration timeout) throws InterruptedException {
        if (timeout.isZero()) {
            latch.await();
            return true;
        }
        return latch.await(toNanosSaturated(timeout), TimeUnit.NANOSECONDS);
    }

    private static long toNanosSaturated(final Duration duration) {
        try {
            return duration.toNanos();
        } catch (ArithmeticException e) {
            return duration.isNegative() ? Long.MIN_VALUE : Long.MAX_VALUE;
        }
    }
}
