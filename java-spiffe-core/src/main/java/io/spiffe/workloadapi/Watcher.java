package io.spiffe.workloadapi;

/**
 * Watches updates of type T.
 *
 * @param <T> is the type of the updates.
 */
public interface Watcher<T> {

    /**
     * Method called in case of success getting an update.
     * @param update the instance of type T
     */
    void onUpdate(final T update);

    /**
     * Method called in case there is an error watching for updates.
     * @param e the throwable exception that was caught
     */
    void onError(final Throwable e);
}
