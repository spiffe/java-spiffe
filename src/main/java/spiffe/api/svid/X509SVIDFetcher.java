package spiffe.api.svid;

import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import spiffe.api.svid.retry.RetryHandler;
import spiffe.api.svid.retry.RetryPolicy;

import java.util.List;
import java.util.function.Consumer;

import static spiffe.api.svid.Workload.*;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Provides functionality to interact with a Workload API
 *
 */
public final class X509SVIDFetcher implements Fetcher<List<X509SVID>> {

    private static final Logger LOGGER = Logger.getLogger(X509SVIDFetcher.class.getName());

    private SpiffeWorkloadStub spiffeWorkloadStub;

    private RetryHandler retryHandler;


    /**
     * Constructor
     * @param spiffeEndpointAddress
     */
    public X509SVIDFetcher(String spiffeEndpointAddress) {
        spiffeWorkloadStub = new SpiffeWorkloadStub(spiffeEndpointAddress);
        retryHandler = new RetryHandler(new RetryPolicy());
    }

    /**
     * Constructor
     * @param spiffeEndpointAddress
     */
    public X509SVIDFetcher(String spiffeEndpointAddress, RetryPolicy retryPolicy) {
        spiffeWorkloadStub = new SpiffeWorkloadStub(spiffeEndpointAddress);
        retryHandler = new RetryHandler(retryPolicy);
    }

    /**
     * Default constructor
     *
     * The Spiffe Endpoint Address will be read from the system property 'spiffe.endpoint_socket'
     * and then in second order of priority from the environment variable 'SPIFFE_ENDPOINT_SOCKET'
     * If the endpoint address it's not found, an IllegalStateException will be thrown.
     *
     */
    public X509SVIDFetcher() {
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
                LOGGER.log(Level.INFO, "New SVID received ");
                listener.accept(value.getSvidsList());
                retryHandler.reset();
            }

            @Override
            public void onError(Throwable t) {
                LOGGER.log(Level.SEVERE, String.format("Could not get SVID \n %s", t.getMessage()));
                if (isRetryableError(t)) {
                    retryHandler.scheduleRetry(() -> registerListener(listener));
                }
            }

            @Override
            public void onCompleted() {
            }
        };

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
