package spiffe.provider;

import java.util.concurrent.locks.StampedLock;
import java.util.function.Supplier;

/**
 * Functional Template for performing synchronized reads and writes
 * Uses a StampedLock to handle locks
 *
 */
class FunctionalReadWriteLock {

    private final StampedLock lock;

    FunctionalReadWriteLock() {
        this.lock = new StampedLock();
    }

    <T> T read(Supplier<T> supplier) {
        long stamp = lock.tryOptimisticRead();
        T value = supplier.get();
        if (lock.validate(stamp)) {
            return value;
        }
        stamp = lock.readLock();
        try {
            return supplier.get();
        } finally {
            lock.unlockRead(stamp);
        }
    }

    void write(Runnable runnable) {
        long stamp = lock.writeLock();
        try {
            runnable.run();
        } finally {
            lock.unlockWrite(stamp);
        }
    }
}
