package spiffe.result;

import lombok.Value;

import java.util.NoSuchElementException;

/**
 * An {@code Error} represents a Result that conveys an error of type E.
 *
 * @param <V> the type of the value conveyed by the Result
 * @param <E> the type of the error wrapped in the Error
 */
@Value
public class Error<V, E> implements Result<V, E> {

    E error;

    Error(final E error) {
        this.error = error;
    }

    /**
     * @throws NoSuchElementException, Error does not contain any value.
     */
    @Override
    public V getValue() {
        throw new NoSuchElementException("No value present in Error");
    }

    @Override
    public boolean isOk() {
        return false;
    }

    @Override
    public boolean isError() {
        return true;
    }
}
