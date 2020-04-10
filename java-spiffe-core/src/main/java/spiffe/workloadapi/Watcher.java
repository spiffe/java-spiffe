package spiffe.workloadapi;

import spiffe.result.Error;

/**
 * a <code>Watcher</code> handles updates of type T.
 *
 * @param <T> is the type of the updates.
 */
public interface Watcher<T> {

    void OnUpdate(final T update);

    void OnError(final Error<T, Throwable> t);
}
