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
public final class WorkloadAPIClient {

    private static Logger LOGGER = LoggerFactory.getLogger(WorkloadAPIClient.class);

    private SpiffeWorkloadStub spiffeWorkloadStub;

    private RetryHandler retryHandler;


    /**
     * Constructor
     * @param spiffeEndpointAddress
     */
    public WorkloadAPIClient(String spiffeEndpointAddress) {
        spiffeWorkloadStub = new SpiffeWorkloadStub(spiffeEndpointAddress);
        retryHandler = new RetryHandler(new RetryPolicy(1, 60, TimeUnit.SECONDS));
    }

    /**
     * Constructor
     * @param spiffeEndpointAddress
     */
    public WorkloadAPIClient(String spiffeEndpointAddress, RetryPolicy retryPolicy) {
        spiffeWorkloadStub = new SpiffeWorkloadStub(spiffeEndpointAddress);
        retryHandler = new RetryHandler(retryPolicy);
    }

    /**
     * Default constructor
     *
     */
    public WorkloadAPIClient() {
        this(null);

    }

    /**
     * Fetch the SVIDs from the Workload API on a asynchronous fashion
     *
     */
    public void fetchX509SVIDs(Consumer<List<X509SVID>> listener) {

        StreamObserver<X509SVIDResponse> observer = new StreamObserver<X509SVIDResponse>() {
            @Override
            public void onNext(X509SVIDResponse value) {
                listener.accept(value.getSvidsList());
            }

            @Override
            public void onError(Throwable t) {
                LOGGER.error(t.getMessage());
                if (isRetryableError(t)) {
                    retryHandler.scheduleRetry(() -> fetchX509SVIDs(listener));
                }
            }

            @Override
            public void onCompleted() {
            }
        };

        LOGGER.info("Calling fetchX509SVIDs");
        spiffeWorkloadStub.fetchX509SVIDs(newRequest(), observer);
    }

    /**
     * Checks that the error is retryable. The only error that is not retryable is 'InvalidArgument',
     * that occurs when the security header is not present
     * @param t
     * @return
     */
    private boolean isRetryableError(Throwable t) {
        return !"InvalidArgument".equalsIgnoreCase(Status.fromThrowable(t).getCode().name());
    }

    private X509SVIDRequest newRequest() {
        return X509SVIDRequest.newBuilder().build();
    }

}
