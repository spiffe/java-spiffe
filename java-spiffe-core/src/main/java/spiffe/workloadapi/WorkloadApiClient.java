package spiffe.workloadapi;

import io.grpc.Context;
import io.grpc.ManagedChannel;
import io.grpc.stub.StreamObserver;
import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.extern.java.Log;
import lombok.val;
import org.apache.commons.lang3.NotImplementedException;
import org.apache.commons.lang3.StringUtils;
import spiffe.bundle.jwtbundle.JwtBundleSet;
import spiffe.exception.SocketEndpointAddressException;
import spiffe.exception.X509ContextException;
import spiffe.exception.X509SvidException;
import spiffe.spiffeid.SpiffeId;
import spiffe.svid.jwtsvid.JwtSvid;
import spiffe.workloadapi.internal.GrpcConversionUtils;
import spiffe.workloadapi.internal.GrpcManagedChannelFactory;
import spiffe.workloadapi.internal.SecurityHeaderInterceptor;
import spiffe.workloadapi.internal.SpiffeWorkloadAPIGrpc;
import spiffe.workloadapi.internal.SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIBlockingStub;
import spiffe.workloadapi.internal.SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIStub;

import java.io.Closeable;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import static spiffe.workloadapi.internal.Workload.X509SVIDRequest;
import static spiffe.workloadapi.internal.Workload.X509SVIDResponse;

/**
 * A <code>WorkloadApiClient</code> represents a client to interact with the Workload API.
 * Supports one-shot calls and watch updates for X.509 and JWT SVIDS and bundles.
 */
@Log
public class WorkloadApiClient implements Closeable {

    private final SpiffeWorkloadAPIStub workloadApiAsyncStub;
    private final SpiffeWorkloadAPIBlockingStub workloadApiBlockingStub;
    private final ManagedChannel managedChannel;
    private final List<Context.CancellableContext> cancellableContexts;

    private WorkloadApiClient(SpiffeWorkloadAPIStub workloadApiAsyncStub, SpiffeWorkloadAPIBlockingStub workloadApiBlockingStub, ManagedChannel managedChannel) {
        this.workloadApiAsyncStub = workloadApiAsyncStub;
        this.workloadApiBlockingStub = workloadApiBlockingStub;
        this.managedChannel = managedChannel;
        this.cancellableContexts = Collections.synchronizedList(new ArrayList<>());
    }

    /**
     * Creates a new Workload API client using the default socket endpoint address.
     * @see Address#getDefaultAddress()
     *
     * @return a {@link WorkloadApiClient}
     */
    public static WorkloadApiClient newClient() throws SocketEndpointAddressException {
        val options = ClientOptions.builder().build();
        return newClient(options);
    }

    /**
     * Creates a new Workload API client.
     * <p>
     * If the SPIFFE socket endpoint address is not provided in the options, it uses the default address.
     *
     * @param options {@link ClientOptions}
     * @return a {@link WorkloadApiClient}
     */
    public static WorkloadApiClient newClient(@NonNull ClientOptions options) throws SocketEndpointAddressException {
        String spiffeSocketPath;
        if (StringUtils.isNotBlank(options.spiffeSocketPath)) {
            spiffeSocketPath = options.spiffeSocketPath;
        } else {
            spiffeSocketPath = Address.getDefaultAddress();
        }

        val socketEndpointAddress = Address.parseAddress(spiffeSocketPath);
        val managedChannel = GrpcManagedChannelFactory.newChannel(socketEndpointAddress);

        val workloadAPIAsyncStub = SpiffeWorkloadAPIGrpc
                .newStub(managedChannel)
                .withInterceptors(new SecurityHeaderInterceptor());

        val workloadAPIBlockingStub = SpiffeWorkloadAPIGrpc
                .newBlockingStub(managedChannel)
                .withInterceptors(new SecurityHeaderInterceptor());

        return new WorkloadApiClient(workloadAPIAsyncStub, workloadAPIBlockingStub, managedChannel);
    }

    /**
     * One-shot blocking fetch call to get an X.509 context.
     *
     * @throws X509ContextException if there is an error fetching or processing the X.509 context
     */
    public X509Context fetchX509Context() {
        Context.CancellableContext cancellableContext;
        cancellableContext = Context.current().withCancellation();
        X509Context result;
        try {
            result = cancellableContext.call(this::processX509Context);
        } catch (Exception e) {
            throw new X509ContextException("Error fetching X509Context", e);
        }
        // close connection
        cancellableContext.close();
        return result;
    }

    /**
     * Watches for X.509 context updates.
     *
     * @param watcher an instance that implements a {@link Watcher}.
     */
    public void watchX509Context(Watcher<X509Context> watcher) {
        StreamObserver<X509SVIDResponse> streamObserver = new StreamObserver<X509SVIDResponse>() {
            @Override
            public void onNext(X509SVIDResponse value) {
                X509Context x509Context = null;
                try {
                    x509Context = GrpcConversionUtils.toX509Context(value);
                } catch (CertificateException | X509SvidException e) {
                    watcher.onError(new X509ContextException("Error processing X509 Context update", e));
                }
                watcher.onUpdate(x509Context);
            }

            @Override
            public void onError(Throwable t) {
                watcher.onError(new X509ContextException("Error getting X509Context", t));
            }

            @Override
            public void onCompleted() {
                watcher.onError(new X509ContextException("Unexpected completed stream"));
            }
        };
        Context.CancellableContext cancellableContext;
        cancellableContext = Context.current().withCancellation();
        cancellableContext.run(() -> workloadApiAsyncStub.fetchX509SVID(newX509SvidRequest(), streamObserver));
        this.cancellableContexts.add(cancellableContext);
    }

    /**
     * One-shot fetch call to get a SPIFFE JWT-SVID.
     *
     * @param subject       a SPIFFE ID
     * @param audience      the audience of the JWT-SVID
     * @param extraAudience the extra audience for the JWT_SVID
     *
     * @return an instance of a {@link JwtSvid}
     *
     * @throws //TODO: declare thrown exceptions
     */
    public JwtSvid fetchJwtSvid(SpiffeId subject, String audience, String... extraAudience) {
        throw new NotImplementedException("Not implemented");
    }

    /**
     * Fetches the JWT bundles for JWT-SVID validation, keyed by trust domain.
     *
     * @return an instance of a {@link JwtBundleSet}
     * @throws //TODO: declare thrown exceptions
     */
    public JwtBundleSet fetchJwtBundles() {
        throw new NotImplementedException("Not implemented");
    }

    /**
     * Validates the JWT-SVID token. The parsed and validated
     * JWT-SVID is returned.
     *
     * @param token    JWT token
     * @param audience audience of the JWT
     * @return the {@link JwtSvid} if the token and audience could be validated.
     *
     * @throws //TODO: declare thrown exceptions
     */
    public JwtSvid validateJwtSvid(String token, String audience) {
        throw new NotImplementedException("Not implemented");
    }

    /**
     * Watches for JWT bundles updates.
     *
     * @param jwtBundlesWatcher receives the update for JwtBundles.
     */
    public void watchJwtBundles(Watcher<JwtBundleSet> jwtBundlesWatcher) {
        throw new NotImplementedException("Not implemented");
    }

    /**
     * Closes this Workload API closing the underlying channel and cancelling the contexts.
     */
    @Override
    public void close() {
        log.info("Closing WorkloadAPI client");
        synchronized (this) {
            for (val context : cancellableContexts) {
                context.close();
            }
            log.info("Shutting down Managed Channel");
            managedChannel.shutdown();
        }
    }

    private X509SVIDRequest newX509SvidRequest() {
        return X509SVIDRequest.newBuilder().build();
    }

    private X509Context processX509Context() {
        try {
            Iterator<X509SVIDResponse> x509SVIDResponse = workloadApiBlockingStub.fetchX509SVID(newX509SvidRequest());
            if (x509SVIDResponse.hasNext()) {
                return GrpcConversionUtils.toX509Context(x509SVIDResponse.next());
            }
        } catch (Exception e) {
            throw new X509ContextException("Error processing X509Context", e);
        }
        throw new X509ContextException("Error processing X509Context: x509SVIDResponse is empty");
    }

    /**
     * Options for creating a new {@link WorkloadApiClient}.
     */
    @Data
    public static class ClientOptions {
        String spiffeSocketPath;

        @Builder
        public ClientOptions(String spiffeSocketPath) {
            this.spiffeSocketPath = spiffeSocketPath;
        }
    }
}
