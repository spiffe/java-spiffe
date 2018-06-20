package spiffe.api.svid;

import java.util.function.Consumer;

public interface Fetcher<T> {

    void registerListener(Consumer<T> listener);
}
