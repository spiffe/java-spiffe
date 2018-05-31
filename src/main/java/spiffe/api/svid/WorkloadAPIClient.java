package spiffe.api.svid;

import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Function;

import static spiffe.api.svid.Workload.*;

/**
 * Provides functionality to interact with a Workload API
 *
 */
public final class WorkloadAPIClient {

    private static Logger LOGGER = LoggerFactory.getLogger(WorkloadAPIClient.class);

    private SpiffeWorkloadStub spiffeWorkloadStub;

    private ScheduledExecutorService scheduledExecutorService = Executors.newScheduledThreadPool(1);
    private RetryState retryState = new RetryState(1, 60, TimeUnit.SECONDS);

    /**
     * Constructor
     * @param spiffeEndpointAddress
     */
    public WorkloadAPIClient(String spiffeEndpointAddress) {
        spiffeWorkloadStub = new SpiffeWorkloadStub(spiffeEndpointAddress);
    }

    /**
     * Default constructor
     *
     */
    public WorkloadAPIClient() {
        spiffeWorkloadStub = new SpiffeWorkloadStub();
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
                    scheduledExecutorService.schedule(
                            () -> fetchX509SVIDs(listener), retryState.delay(), retryState.timeUnit);
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

    static class RetryState  {
        RetryState(long delay, long maxDelay, TimeUnit timeUnit) {
            if (delay < 1) {
                this.delay = 1;
            } else {
                this.delay = delay;
            }
            this.maxDelay = maxDelay;
            this.timeUnit = timeUnit;
        }

        private long delay;
        private long maxDelay;
        private TimeUnit timeUnit;
        private Function<Long, Long> calculateDelay = (d) -> d * 2;

        long delay() {
            delay = calculateDelay.apply(delay);
            if (delay > maxDelay) {
                delay = maxDelay;
            }
            return delay;
        }
    }
}
