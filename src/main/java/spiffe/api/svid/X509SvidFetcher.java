package spiffe.api.svid;

import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spiffe.api.svid.retry.RetryHandler;
import spiffe.api.svid.retry.RetryPolicy;

import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import static spiffe.api.svid.Workload.*;

/**
 * Provides functionality to interact with a Workload API
 *
 */
public final class X509SvidFetcher implements Fetcher<List<X509SVID>> {

    private static Logger LOGGER = LoggerFactory.getLogger(X509SvidFetcher.class);

    private SpiffeWorkloadStub spiffeWorkloadStub;

    private RetryHandler retryHandler;


    /**
     * Constructor
     * @param spiffeEndpointAddress
     */
    public X509SvidFetcher(String spiffeEndpointAddress) {
        spiffeWorkloadStub = new SpiffeWorkloadStub(spiffeEndpointAddress);
        retryHandler = new RetryHandler(new RetryPolicy());
    }

    /**
     * Constructor
     * @param spiffeEndpointAddress
     */
    public X509SvidFetcher(String spiffeEndpointAddress, RetryPolicy retryPolicy) {
        spiffeWorkloadStub = new SpiffeWorkloadStub(spiffeEndpointAddress);
        retryHandler = new RetryHandler(retryPolicy);
    }

    /**
     * Default constructor
     *
     */
    public X509SvidFetcher() {
        this(null);

    }

    /**
     * Register the listener to receive the X509 SVIDS from the Workload API
     * In case there's an error in the connection with the Workload API,
     * it retries using a RetryHandler that implements a backoff policy
     *
     */
    @Override
    public void registerListener(Consumer<List<X509SVID>> listener) {

        StreamObserver<X509SVIDResponse> observer = new StreamObserver<X509SVIDResponse>() {
            @Override
            public void onNext(X509SVIDResponse value) {
                listener.accept(value.getSvidsList());
            }

            @Override
            public void onError(Throwable t) {
                LOGGER.error(t.getMessage());
                if (isRetryableError(t)) {
                    retryHandler.scheduleRetry(() -> registerListener(listener));
                }
            }

            @Override
            public void onCompleted() {
            }
        };

        LOGGER.info("Calling registerListener");
        spiffeWorkloadStub.fetchX509SVIDs(newRequest(), observer);
    }

    /**
     * Checks that the error is retryable. The only error that is not retryable is 'INVALID_ARGUMENT',
     * that occurs when the security header is not present
     * @param t
     * @return
     */
    private boolean isRetryableError(Throwable t) {
        return !"INVALID_ARGUMENT".equalsIgnoreCase(Status.fromThrowable(t).getCode().name());
    }

    private X509SVIDRequest newRequest() {
        return X509SVIDRequest.newBuilder().build();
    }

}
