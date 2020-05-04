package spiffe.workloadapi;

import io.grpc.Context;
import io.grpc.Status;
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
import spiffe.workloadapi.internal.*;
import spiffe.workloadapi.internal.SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIBlockingStub;
import spiffe.workloadapi.internal.SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIStub;
import spiffe.workloadapi.retry.BackoffPolicy;
import spiffe.workloadapi.retry.RetryHandler;

import java.io.Closeable;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.logging.Level;

import static spiffe.workloadapi.internal.Workload.X509SVIDRequest;
import static spiffe.workloadapi.internal.Workload.X509SVIDResponse;

/**
 * A <code>WorkloadApiClient</code> represents a client to interact with the Workload API.
 * <p>
 * Supports one-shot calls and watch updates for X.509 and JWT SVIDs and bundles.
 * <p>
 * The watch for updates methods support retries using an exponential backoff policy to reestablish
 * the stream connection to the Workload API.
 */
@Log
public class WorkloadApiClient implements Closeable {

    private static final String INVALID_ARGUMENT = "INVALID_ARGUMENT";

    private final SpiffeWorkloadAPIStub workloadApiAsyncStub;
    private final SpiffeWorkloadAPIBlockingStub workloadApiBlockingStub;
    private final ManagedChannelWrapper managedChannel;
    private final List<Context.CancellableContext> cancellableContexts;
    private final BackoffPolicy backoffPolicy;

    // using a scheduled executor service to be able to schedule retries
    // it is injected in each of the retryHandlers in the watch methods
    private final ScheduledExecutorService retryExecutor;

    private ExecutorService executorService;

    private boolean closed;

    private WorkloadApiClient(SpiffeWorkloadAPIStub workloadApiAsyncStub,
                              SpiffeWorkloadAPIBlockingStub workloadApiBlockingStub,
                              ManagedChannelWrapper managedChannel,
                              BackoffPolicy backoffPolicy,
                              ScheduledExecutorService retryExecutor,
                              ExecutorService executorService) {
        this.workloadApiAsyncStub = workloadApiAsyncStub;
        this.workloadApiBlockingStub = workloadApiBlockingStub;
        this.managedChannel = managedChannel;
        this.cancellableContexts = Collections.synchronizedList(new ArrayList<>());
        this.backoffPolicy = backoffPolicy;
        this.retryExecutor = retryExecutor;
        this.executorService = executorService;
    }

    /**
     * Creates a new Workload API client using the default socket endpoint address.
     *
     * @return a {@link WorkloadApiClient}
     * @see Address#getDefaultAddress()
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

        if (options.backoffPolicy == null) {
            options.backoffPolicy = new BackoffPolicy();
        }

        if (options.executorService == null) {
            options.executorService = Executors.newCachedThreadPool();
        }

        val socketEndpointAddress = Address.parseAddress(spiffeSocketPath);
        val managedChannel = GrpcManagedChannelFactory.newChannel(socketEndpointAddress, options.executorService);
        val workloadAPIAsyncStub = SpiffeWorkloadAPIGrpc
                .newStub(managedChannel.getChannel())
                .withExecutor(options.executorService)
                .withInterceptors(new SecurityHeaderInterceptor());

        val workloadAPIBlockingStub = SpiffeWorkloadAPIGrpc
                .newBlockingStub(managedChannel.getChannel())
                .withExecutor(options.executorService)
                .withInterceptors(new SecurityHeaderInterceptor());

        val retryExecutor = Executors.newSingleThreadScheduledExecutor();

        return new WorkloadApiClient(
                workloadAPIAsyncStub,
                workloadAPIBlockingStub,
                managedChannel,
                options.backoffPolicy,
                retryExecutor,
                options.executorService);
    }

    /**
     * One-shot blocking fetch call to get an X.509 context.
     *
     * @throws X509ContextException if there is an error fetching or processing the X.509 context
     */
    public X509Context fetchX509Context() throws X509ContextException {
        try (val cancellableContext = Context.current().withCancellation()) {
            return cancellableContext.call(this::processX509Context);
        } catch (Exception e) {
            throw new X509ContextException("Error fetching X509Context", e);
        }
    }

    /**
     * Watches for X.509 context updates.
     *
     * @param watcher an instance that implements a {@link Watcher}.
     */
    public void watchX509Context(Watcher<X509Context> watcher) {
        val retryHandler = new RetryHandler(backoffPolicy, retryExecutor);
        val cancellableContext = Context.current().withCancellation();

        val streamObserver = getX509ContextStreamObserver(watcher, retryHandler, cancellableContext);

        cancellableContext.run(() -> workloadApiAsyncStub.fetchX509SVID(newX509SvidRequest(), streamObserver));
        this.cancellableContexts.add(cancellableContext);
    }

    private StreamObserver<X509SVIDResponse> getX509ContextStreamObserver(Watcher<X509Context> watcher, RetryHandler retryHandler, Context.CancellableContext cancellableContext) {
        return new StreamObserver<X509SVIDResponse>() {
            @Override
            public void onNext(X509SVIDResponse value) {
                try {
                    X509Context x509Context = GrpcConversionUtils.toX509Context(value);
                    watcher.onUpdate(x509Context);
                    retryHandler.reset();
                } catch (CertificateException | X509SvidException e) {
                    watcher.onError(new X509ContextException("Error processing X509 Context update", e));
                }
            }

            @Override
            public void onError(Throwable t) {
                handleWatchX509ContextError(t);
            }

            private void handleWatchX509ContextError(Throwable t) {
                if (INVALID_ARGUMENT.equals(Status.fromThrowable(t).getCode().name())) {
                    watcher.onError(new X509ContextException("Canceling X509 Context watch", t));
                } else {
                    log.log(Level.INFO, "Retrying connecting to Workload API to register X509 context watcher");
                    retryHandler.scheduleRetry(() ->
                            cancellableContext.run(() -> workloadApiAsyncStub.fetchX509SVID(newX509SvidRequest(), this)));
                }
            }

            @Override
            public void onCompleted() {
                cancellableContext.close();
                watcher.onError(new X509ContextException("Unexpected completed stream"));
            }
        };
    }

    /**
     * One-shot fetch call to get a SPIFFE JWT-SVID.
     *
     * @param subject       a SPIFFE ID
     * @param audience      the audience of the JWT-SVID
     * @param extraAudience the extra audience for the JWT_SVID
     * @return an instance of a {@link JwtSvid}
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
     * Closes this Workload API closing the underlying channel,
     * cancelling the contexts and shutdown the executor service.
     */
    @Override
    public void close() {
        log.log(Level.FINE, "Closing WorkloadAPI client");
        synchronized (this) {
            if (!closed) {
                closed = true;
                for (val context : cancellableContexts) {
                    context.close();
                }
                managedChannel.close();
                retryExecutor.shutdown();
                executorService.shutdown();
            }
        }
        log.log(Level.INFO, "WorkloadAPI client is closed");
    }

    private X509SVIDRequest newX509SvidRequest() {
        return X509SVIDRequest.newBuilder().build();
    }

    private X509Context processX509Context() throws X509ContextException {
        try {
            Iterator<X509SVIDResponse> x509SVIDResponse = workloadApiBlockingStub.fetchX509SVID(newX509SvidRequest());
            if (x509SVIDResponse.hasNext()) {
                return GrpcConversionUtils.toX509Context(x509SVIDResponse.next());
            }
        } catch (CertificateException | X509SvidException e) {
            throw new X509ContextException("Error processing X509Context", e);
        }
        throw new X509ContextException("Error processing X509Context: x509SVIDResponse is empty");
    }

    /**
     * Options for creating a new {@link WorkloadApiClient}. The {@link BackoffPolicy}  is used
     * to configure a {@link RetryHandler} to perform retries to reconnect to the Workload API.
     */
    @Data
    public static class ClientOptions {
        String spiffeSocketPath;
        BackoffPolicy backoffPolicy;
        ExecutorService executorService;

        @Builder
        public ClientOptions(String spiffeSocketPath, BackoffPolicy backoffPolicy, ExecutorService executorService) {
            this.spiffeSocketPath = spiffeSocketPath;
            this.backoffPolicy = backoffPolicy;
            this.executorService = executorService;
        }
    }
}
