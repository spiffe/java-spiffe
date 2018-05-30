package spiffe.api.svid;

import io.grpc.stub.StreamObserver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.function.Consumer;

import static org.apache.commons.lang3.StringUtils.EMPTY;
import static spiffe.api.svid.Workload.*;

/**
 * Provides functionality to interact with a Workload API
 *
 */
public final class WorkloadAPIClient {

    private static Logger LOGGER = LoggerFactory.getLogger(WorkloadAPIClient.class);

    private SpiffeWorkloadStub spiffeWorkloadStub;

    /**
     * Constructor
     * @param spiffeEndpointAddress
     */
    public WorkloadAPIClient(String spiffeEndpointAddress) {
        spiffeWorkloadStub = new SpiffeWorkloadStub(spiffeEndpointAddress);
    }

    /**
     * Default constructor
     * The WorkloadAPI Address will be resolved by an Environment Variable
     *
     */
    public WorkloadAPIClient() {
        spiffeWorkloadStub = new SpiffeWorkloadStub(EMPTY);
    }

    /**
     * Fetch the SVIDs from the Workload API on a asynchronous fashion
     *
     * TODO: Use a Exponential Backoff to handle the errors and retries
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
            }

            @Override
            public void onCompleted() {
            }
        };

        spiffeWorkloadStub.fetchX509SVIDs(newRequest(), observer);
    }

    private X509SVIDRequest newRequest() {
        return X509SVIDRequest.newBuilder().build();
    }
}
