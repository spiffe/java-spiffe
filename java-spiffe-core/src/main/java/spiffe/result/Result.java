package spiffe.result;

import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * A <code>Result</code> represents the result of an operation, that can be {@link spiffe.result.Ok} or {@link spiffe.result.Error}.
 * <p>
 * This is a very simple implementation that accomplishes its purpose on this library,
 * doesn't contain all the functionality that is required to be a fully monadic type.
 *
 * @param <V> type of the value conveyed by the Result
 * @param <E> type of the error conveyed by the Result.
 *
 * @see Ok
 * @see Error
 */
public interface Result<V, E> {

    V getValue();

    E getError();

    boolean isOk();

    boolean isError();

    static <V, E> Ok<V, E> ok(final V value) {
        return new Ok<>(value);
    }

    static <V, E> Error<V, E> error(final E error) {
        return new Error<>(error);
    }


    /**
     * Applies the Function if the actual Result is an Ok.
     *
     * @param fn Function to apply, receives a superclass of U and returns a Result of T
     * @param u Parameter of the Function
     * @param <U> Type of the parameter of the Function
     * @return A Result of type V.
     */
    default <U> Result<V, E> thenApply(Function<? super U, Result<V, E>> fn, U u) {
        if (this.isOk()) {
            return fn.apply(u);
        }
        return this;
    }

    /**
     * Applies the BiFunction if the actual Result is an Ok.
     *
     * @param fn Function to apply, receives a superclass of U and returns a Result of T
     * @param u First parameter of the BiFunction
     * @param s Second parameter of the BiFunction
     * @param <U> Type of the parameter of the BiFunction
     * @return A Result of type V.
     */
    default <U, S> Result<V, E> thenApply(BiFunction<? super U, ? super S, Result<V, E>> fn, U u, S s) {
        if (this.isOk()) {
            return fn.apply(u, s);
        }
        return this;
    }
}
