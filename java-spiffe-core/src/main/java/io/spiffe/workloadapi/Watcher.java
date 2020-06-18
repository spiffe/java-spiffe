package io.spiffe.workloadapi;

/**
 * Watches updates of type T.
 *
 * @param <T> is the type of the updates.
 */
public interface Watcher<T> {
    void onUpdate(final T update);
    void onError(final Throwable e);
}
