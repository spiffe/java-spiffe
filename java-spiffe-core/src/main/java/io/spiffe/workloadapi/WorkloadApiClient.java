package io.spiffe.workloadapi;

import io.grpc.Context;
import io.spiffe.bundle.jwtbundle.JwtBundleSet;
import io.spiffe.exception.JwtBundleException;
import io.spiffe.exception.JwtSvidException;
import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.exception.X509ContextException;
import io.spiffe.exception.X509SvidException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.svid.jwtsvid.JwtSvid;
import io.spiffe.workloadapi.grpc.SpiffeWorkloadAPIGrpc;
import io.spiffe.workloadapi.grpc.SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIBlockingStub;
import io.spiffe.workloadapi.grpc.SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIStub;
import io.spiffe.workloadapi.grpc.Workload;
import io.spiffe.workloadapi.internal.GrpcManagedChannelFactory;
import io.spiffe.workloadapi.internal.ManagedChannelWrapper;
import io.spiffe.workloadapi.internal.SecurityHeaderInterceptor;
import io.spiffe.workloadapi.retry.BackoffPolicy;
import io.spiffe.workloadapi.retry.RetryHandler;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.Setter;
import lombok.extern.java.Log;
import lombok.val;
import org.apache.commons.lang3.StringUtils;

import java.io.Closeable;
import java.security.KeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.logging.Level;

import static io.spiffe.workloadapi.StreamObservers.getJwtBundleStreamObserver;
import static io.spiffe.workloadapi.StreamObservers.getX509ContextStreamObserver;

/**
 * Represents a client to interact with the Workload API.
 * <p>
 * Supports one-shot calls and watch updates for X.509 and JWT SVIDs and bundles.
 * <p>
 * The watch for updates methods support retries using an exponential backoff policy to reestablish
 * the stream connection to the Workload API.
 */
@Log
public final class WorkloadApiClient implements Closeable {

    private final SpiffeWorkloadAPIStub workloadApiAsyncStub;
    private final SpiffeWorkloadAPIBlockingStub workloadApiBlockingStub;
    private final ManagedChannelWrapper managedChannel;
    private final List<Context.CancellableContext> cancellableContexts;
    private final BackoffPolicy backoffPolicy;

    // using a scheduled executor service to be able to schedule retries
    // it is injected in each of the retryHandlers in the watch methods
    private final ScheduledExecutorService retryExecutor;

    private final ExecutorService executorService;

    private boolean closed;

    private WorkloadApiClient(final SpiffeWorkloadAPIStub workloadApiAsyncStub,
                              final SpiffeWorkloadAPIBlockingStub workloadApiBlockingStub,
                              final ManagedChannelWrapper managedChannel,
                              final BackoffPolicy backoffPolicy,
                              final ScheduledExecutorService retryExecutor,
                              final ExecutorService executorService) {
        this.workloadApiAsyncStub = workloadApiAsyncStub;
        this.workloadApiBlockingStub = workloadApiBlockingStub;
        this.managedChannel = managedChannel;
        this.cancellableContexts = Collections.synchronizedList(new ArrayList<>());
        this.backoffPolicy = backoffPolicy;
        this.retryExecutor = retryExecutor;
        this.executorService = executorService;
    }

    /**
     * Constructor
     * <p>
     * It is recommended to use the facility methods `newClient()` to get a new instance
     * of the WorkloadApiClient.
     *
     * @param workloadApiAsyncStub    a {@link SpiffeWorkloadAPIStub}
     * @param workloadApiBlockingStub a {@link SpiffeWorkloadAPIBlockingStub}
     * @param managedChannel          a {@link ManagedChannelWrapper}
     */
    public WorkloadApiClient(final SpiffeWorkloadAPIStub workloadApiAsyncStub,
                             final SpiffeWorkloadAPIBlockingStub workloadApiBlockingStub,
                             final ManagedChannelWrapper managedChannel) {
        this.workloadApiAsyncStub = workloadApiAsyncStub;
        this.workloadApiBlockingStub = workloadApiBlockingStub;
        this.backoffPolicy = new BackoffPolicy();
        this.executorService = Executors.newCachedThreadPool();
        this.retryExecutor = Executors.newSingleThreadScheduledExecutor();
        this.cancellableContexts = Collections.synchronizedList(new ArrayList<>());
        this.managedChannel = managedChannel;
    }

    /**
     * Creates a new Workload API client using the default socket endpoint address.
     *
     * @return a {@link WorkloadApiClient}
     * @throws SocketEndpointAddressException if the Workload API socket endpoint address is not valid
     * @see Address#getDefaultAddress()
     */
    public static WorkloadApiClient newClient() throws SocketEndpointAddressException {
        val options = ClientOptions.builder().build();
        return newClient(options);
    }

    /**
     * Creates a new Workload API client configured with the given client options.
     * <p>
     * If the SPIFFE socket endpoint address is not provided in the options, it uses the default address.
     *
     * @param options {@link ClientOptions}
     * @return a {@link WorkloadApiClient}
     * @throws SocketEndpointAddressException if the Workload API socket endpoint address is not valid
     */
    public static WorkloadApiClient newClient(@NonNull final ClientOptions options)
            throws SocketEndpointAddressException {
        final String spiffeSocketPath;
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
     * @return an instance of a {@link X509Context} containing the X.509 materials fetched from the Workload API
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
    public void watchX509Context(@NonNull final Watcher<X509Context> watcher) {
        val retryHandler = new RetryHandler(backoffPolicy, retryExecutor);
        val cancellableContext = Context.current().withCancellation();

        val streamObserver =
                getX509ContextStreamObserver(watcher, retryHandler, cancellableContext, workloadApiAsyncStub);

        cancellableContext.run(() -> workloadApiAsyncStub.fetchX509SVID(newX509SvidRequest(), streamObserver));
        this.cancellableContexts.add(cancellableContext);
    }

    /**
     * One-shot fetch call to get a SPIFFE JWT-SVID.
     *
     * @param subject       a SPIFFE ID
     * @param audience      the audience of the JWT-SVID
     * @param extraAudience the extra audience for the JWT_SVID
     * @return an instance of a {@link JwtSvid}
     * @throws JwtSvidException if there is an error fetching or processing the JWT from the Workload API
     */
    public JwtSvid fetchJwtSvid(@NonNull final SpiffeId subject,
                                @NonNull final String audience,
                                final String... extraAudience)
            throws JwtSvidException {

        final Set<String> audParam = new HashSet<>();
        audParam.add(audience);
        Collections.addAll(audParam, extraAudience);

        try (val cancellableContext = Context.current().withCancellation()) {
            return cancellableContext.call(() -> callFetchJwtSvid(subject, audParam));
        } catch (Exception e) {
            throw new JwtSvidException("Error fetching JWT SVID", e);
        }
    }

    /**
     * Fetches the JWT bundles for JWT-SVID validation, keyed by trust domain.
     *
     * @return an instance of a {@link JwtBundleSet}
     * @throws JwtBundleException when there is an error getting or processing the response from the Workload API
     */
    public JwtBundleSet fetchJwtBundles() throws JwtBundleException {
        try (val cancellableContext = Context.current().withCancellation()) {
            return cancellableContext.call(this::callFetchBundles);
        } catch (Exception e) {
            throw new JwtBundleException("Error fetching JWT SVID", e);
        }
    }

    /**
     * Validates the JWT-SVID token. The parsed and validated JWT-SVID is returned.
     *
     * @param token    JWT token
     * @param audience audience of the JWT
     * @return a {@link JwtSvid} if the token and audience could be validated.
     * @throws JwtSvidException when the token cannot be validated with the audience
     */
    public JwtSvid validateJwtSvid(@NonNull final String token, @NonNull final String audience)
            throws JwtSvidException {
        val request = Workload.ValidateJWTSVIDRequest
                .newBuilder()
                .setSvid(token)
                .setAudience(audience)
                .build();

        try (val cancellableContext = Context.current().withCancellation()) {
            cancellableContext.call(() -> workloadApiBlockingStub.validateJWTSVID(request));
        } catch (Exception e) {
            throw new JwtSvidException("Error validating JWT SVID", e);
        }

        return JwtSvid.parseInsecure(token, Collections.singleton(audience));
    }

    /**
     * Watches for JWT bundles updates.
     *
     * @param watcher receives the update for JwtBundles.
     */
    public void watchJwtBundles(@NonNull final Watcher<JwtBundleSet> watcher) {
        val retryHandler = new RetryHandler(backoffPolicy, retryExecutor);
        val cancellableContext = Context.current().withCancellation();

        val streamObserver = getJwtBundleStreamObserver(watcher, retryHandler, cancellableContext, workloadApiAsyncStub);

        cancellableContext.run(() -> workloadApiAsyncStub.fetchJWTBundles(newJwtBundlesRequest(), streamObserver));
        this.cancellableContexts.add(cancellableContext);
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

                if (managedChannel != null) {
                    managedChannel.close();
                }
                retryExecutor.shutdown();
                executorService.shutdown();
            }
        }
        log.log(Level.INFO, "WorkloadAPI client is closed");
    }


    private X509Context processX509Context() throws X509ContextException {
        try {
            val x509SvidResponse = workloadApiBlockingStub.fetchX509SVID(newX509SvidRequest());
            if (x509SvidResponse.hasNext()) {
                return GrpcConversionUtils.toX509Context(x509SvidResponse.next());
            }
        } catch (CertificateException | X509SvidException e) {
            throw new X509ContextException("Error processing X509Context", e);
        }
        throw new X509ContextException("Error processing X509Context: x509SVIDResponse is empty");
    }

    private JwtSvid callFetchJwtSvid(final SpiffeId subject, final Set<String> audience) throws JwtSvidException {
        val jwtSvidRequest = Workload.JWTSVIDRequest.newBuilder()
                .setSpiffeId(subject.toString())
                .addAllAudience(audience)
                .build();
        val response = workloadApiBlockingStub.fetchJWTSVID(jwtSvidRequest);
        return JwtSvid.parseInsecure(response.getSvids(0).getSvid(), audience);
    }

    private JwtBundleSet callFetchBundles() throws JwtBundleException {
        val request = Workload.JWTBundlesRequest.newBuilder().build();
        val bundlesResponse = workloadApiBlockingStub.fetchJWTBundles(request);

        if (bundlesResponse.hasNext()) {
            try {
                return GrpcConversionUtils.toBundleSet(bundlesResponse.next());
            } catch (KeyException | JwtBundleException e) {
                throw new JwtBundleException("Error processing JWT Bundle response from Workload API", e);
            }
        }
        throw new JwtBundleException("JWT Bundle response from the Workload API is empty");
    }

    private Workload.X509SVIDRequest newX509SvidRequest() {
        return Workload.X509SVIDRequest.newBuilder().build();
    }

    private Workload.JWTBundlesRequest newJwtBundlesRequest() {
        return Workload.JWTBundlesRequest.newBuilder().build();
    }

    /**
     * Options for creating a new {@link WorkloadApiClient}.
     * <p>
     * <code>spiffeSocketPath</code> Workload API Socket Endpoint address.
     * <p>
     * <code>backoffPolicy</code> A custom instance of a {@link BackoffPolicy} to configure the retries to reconnect
     * to the Workload API.
     * <p>
     * <code>executorService</code> A custom {@link ExecutorService} to configure the Grpc stubs and channels.
     * If it is not provided, a Executors.newCachedThreadPool() is used by default.
     * The executorService provided will be shutdown when the WorkloadApiClient instance is closed.
     */
    @Data
    public static class ClientOptions {

        @Setter(AccessLevel.NONE)
        private String spiffeSocketPath;

        @Setter(AccessLevel.NONE)
        private BackoffPolicy backoffPolicy;

        @Setter(AccessLevel.NONE)
        private ExecutorService executorService;

        @Builder
        public ClientOptions(final String spiffeSocketPath,
                             final BackoffPolicy backoffPolicy,
                             final ExecutorService executorService) {
            this.spiffeSocketPath = spiffeSocketPath;
            this.backoffPolicy = backoffPolicy;
            this.executorService = executorService;
        }
    }
}
