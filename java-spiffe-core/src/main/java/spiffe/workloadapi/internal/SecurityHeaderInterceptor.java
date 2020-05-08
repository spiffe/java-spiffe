package spiffe.workloadapi.internal;

import io.grpc.*;

public class SecurityHeaderInterceptor implements ClientInterceptor {

    private static final String SECURITY_HEADER = "workload.spiffe.io";

    /**
     * Intercepts the call to the WorkloadAPI and add the required security header
     */
    @Override
    public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(MethodDescriptor<ReqT, RespT> method, CallOptions callOptions, Channel next) {
        return new ForwardingClientCall.SimpleForwardingClientCall<ReqT, RespT>(next.newCall(method, callOptions)) {
            @Override
            public void start(Listener<RespT> responseListener, Metadata headers) {
                Metadata.Key<String> headerKey = Metadata.Key.of(SECURITY_HEADER, Metadata.ASCII_STRING_MARSHALLER);
                headers.put(headerKey, "true");
                super.start(new ForwardingClientCallListener.SimpleForwardingClientCallListener<RespT>(responseListener) {
                }, headers);
            }
        };
    }
}
