package spiffe.provider;

import java.util.concurrent.locks.StampedLock;
import java.util.function.Supplier;

public class FunctionalReadWriteLock {

    private final StampedLock lock;

    public FunctionalReadWriteLock() {
        this.lock = new StampedLock();
    }

    public <T> T read(Supplier<T> supplier) {
        long stamp = lock.readLock();
        try {
            return supplier.get();
        } finally {
            lock.unlockRead(stamp);
        }
    }

    public void write(Runnable runnable) {
        long stamp = lock.writeLock();
        try {
            runnable.run();
        } finally {
            lock.unlockWrite(stamp);
        }
    }
}
