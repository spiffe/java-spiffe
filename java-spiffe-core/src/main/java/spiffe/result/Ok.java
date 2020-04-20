package spiffe.result;

import lombok.Value;

import java.util.NoSuchElementException;

/**
 * An {@link spiffe.result.Ok} represents a Result that conveys a value of type T.
 *
 * @param <V> the type the value wrapped in the Ok result
 * @param <E> the type of the error
 */
@Value
public class Ok<V, E> implements Result<V, E> {

    V value;

    public Ok(final V value) {
        this.value = value;
    }

    @Override
    public V getValue() {
        return value;
    }

    /**
     * @throws NoSuchElementException, Ok does not contain any Error.
     */
    @Override
    public E getError() {
        throw new NoSuchElementException("No error present in an Ok result");
    }

    @Override
    public boolean isOk() {
        return true;
    }

    @Override
    public boolean isError() {
        return false;
    }
}
