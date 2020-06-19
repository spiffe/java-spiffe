package io.spiffe.workloadapi.internal;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class ThreadUtils {

    public static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public static boolean await(CountDownLatch latch, long timeout, TimeUnit unit) {
        boolean result;
        try {
            result = latch.await(timeout, unit);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            result = false;
        }
        return result;
    }

    private ThreadUtils() {
    }
}
