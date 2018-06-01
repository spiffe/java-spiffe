package spiffe.api.svid;

import io.grpc.*;
import io.grpc.stub.StreamObserver;
import spiffe.api.svid.SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIStub;

import static spiffe.api.svid.Workload.*;

/**
 * Wraps and configures a SpiffeWorkloadAPIBlockingStub with a ManagedChannel
 * and an ClientInterceptor to add the SECURITY HEADER
 *
 */
class SpiffeWorkloadStub {

    private static final String SECURITY_HEADER = "workload.spiffe.io";

    private SpiffeWorkloadAPIStub workloadAPIAsyncStub;

    /**
     * Constructor
     * @param spiffeEndpointAddress where the WorkloadAPI is listening. It's validated by
     *                              the channel builder to ensure that it's a correct UDS or TCP address
     */
    SpiffeWorkloadStub(String spiffeEndpointAddress) {
        ManagedChannel managedChannel = SpiffeEndpointChannelBuilder.newChannel(spiffeEndpointAddress);

        workloadAPIAsyncStub= SpiffeWorkloadAPIGrpc
                                        .newStub(managedChannel)
                                        .withInterceptors(new SecurityHeaderInterceptor());
    }

    /**
     * Default constructor
     * As no 'spiffeEndpointAddress' is provided, the channel builder will resolve it through the Environment
     */
    SpiffeWorkloadStub() {
        this(null);
    }

    /**
     * Fetch all bundles running on an async mode
     * @param request
     * @param observer
     *
     */
    public void fetchX509SVIDs(X509SVIDRequest request, StreamObserver<X509SVIDResponse> observer) {
        workloadAPIAsyncStub.fetchX509SVID(request, observer);
    }

    /**
     * Provided the logic for intercepting the call to the WorkloadAPI and add the required security header
     */
    private static class SecurityHeaderInterceptor implements ClientInterceptor {
        @Override
        public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(MethodDescriptor<ReqT, RespT> method, CallOptions callOptions, Channel next) {
            return new ForwardingClientCall.SimpleForwardingClientCall<ReqT, RespT>(next.newCall(method, callOptions)) {
                @Override
                public void start(Listener<RespT> responseListener, Metadata headers) {
                    Metadata.Key<String> headerKey = Metadata.Key.of(SECURITY_HEADER, Metadata.ASCII_STRING_MARSHALLER);
                    headers.put(headerKey, "true");
                    super.start(new ForwardingClientCallListener.SimpleForwardingClientCallListener<RespT>(responseListener) {
                        @Override
                        public void onHeaders(Metadata headers) {
                            super.onHeaders(headers);
                        }
                    }, headers);
                }
            };
        }
    }
}
