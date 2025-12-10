package io.spiffe.workloadapi;

import io.grpc.Context;
import io.grpc.stub.StreamObserver;
import io.spiffe.bundle.jwtbundle.JwtBundleSet;
import io.spiffe.bundle.x509bundle.X509BundleSet;
import io.spiffe.exception.JwtBundleException;
import io.spiffe.exception.JwtSvidException;
import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.exception.X509BundleException;
import io.spiffe.exception.X509ContextException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.svid.jwtsvid.JwtSvid;
import io.spiffe.workloadapi.grpc.SpiffeWorkloadAPIGrpc;
import io.spiffe.workloadapi.grpc.SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIBlockingStub;
import io.spiffe.workloadapi.grpc.SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIStub;
import io.spiffe.workloadapi.grpc.Workload;
import io.spiffe.workloadapi.internal.GrpcManagedChannelFactory;
import io.spiffe.workloadapi.internal.ManagedChannelWrapper;
import io.spiffe.workloadapi.internal.SecurityHeaderInterceptor;
import io.spiffe.workloadapi.retry.ExponentialBackoffPolicy;
import io.spiffe.workloadapi.retry.RetryHandler;
import org.apache.commons.lang3.StringUtils;

import java.net.URI;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.logging.Level;
import java.util.logging.Logger;

import static io.spiffe.workloadapi.StreamObservers.getJwtBundleStreamObserver;
import static io.spiffe.workloadapi.StreamObservers.getX509BundlesStreamObserver;
import static io.spiffe.workloadapi.StreamObservers.getX509ContextStreamObserver;
import static org.apache.commons.lang3.StringUtils.EMPTY;

/**
 * Represents a client to interact with the Workload API.
 * <p>
 * Supports one-shot calls and watch updates for X.509 and JWT SVIDs and bundles.
 * <p>
 * The watch for updates methods support retries using an exponential backoff policy to reestablish
 * the stream connection to the Workload API.
 */
public final class DefaultWorkloadApiClient implements WorkloadApiClient {

    private static final Logger log =
            Logger.getLogger(DefaultWorkloadApiClient.class.getName());

    private final SpiffeWorkloadAPIStub workloadApiAsyncStub;
    private final SpiffeWorkloadAPIBlockingStub workloadApiBlockingStub;
    private final ManagedChannelWrapper managedChannel;
    private final List<Context.CancellableContext> cancellableContexts;
    private final ExponentialBackoffPolicy exponentialBackoffPolicy;

    // using a scheduled executor service to be able to schedule retries
    // it is injected in each of the retryHandlers in the watch methods
    private final ScheduledExecutorService retryExecutor;

    private final ExecutorService executorService;

    private volatile boolean closed;

    private DefaultWorkloadApiClient(final SpiffeWorkloadAPIStub workloadApiAsyncStub,
                                     final SpiffeWorkloadAPIBlockingStub workloadApiBlockingStub,
                                     final ManagedChannelWrapper managedChannel,
                                     final ExponentialBackoffPolicy exponentialBackoffPolicy,
                                     final ScheduledExecutorService retryExecutor,
                                     final ExecutorService executorService) {
        this.workloadApiAsyncStub = workloadApiAsyncStub;
        this.workloadApiBlockingStub = workloadApiBlockingStub;
        this.managedChannel = managedChannel;
        this.cancellableContexts = Collections.synchronizedList(new ArrayList<>());
        this.exponentialBackoffPolicy = exponentialBackoffPolicy;
        this.retryExecutor = retryExecutor;
        this.executorService = executorService;
    }

    DefaultWorkloadApiClient(final SpiffeWorkloadAPIStub workloadApiAsyncStub,
                             final SpiffeWorkloadAPIBlockingStub workloadApiBlockingStub,
                             final ManagedChannelWrapper managedChannel,
                             final ExponentialBackoffPolicy backoffPolicy) {

        this.workloadApiAsyncStub = workloadApiAsyncStub;
        this.workloadApiBlockingStub = workloadApiBlockingStub;
        this.exponentialBackoffPolicy = backoffPolicy;
        this.executorService = Executors.newCachedThreadPool();
        this.retryExecutor = Executors.newSingleThreadScheduledExecutor();
        this.cancellableContexts = Collections.synchronizedList(new ArrayList<>());
        this.managedChannel = managedChannel;
    }

    /**
     * Creates a new Workload API client using the default socket endpoint address.
     * {@link Address#getDefaultAddress()}
     *
     * @return a {@link WorkloadApiClient}, the instance concrete type is {@link DefaultWorkloadApiClient}
     * @throws SocketEndpointAddressException if the Workload API socket endpoint address is not valid
     */
    public static WorkloadApiClient newClient() throws SocketEndpointAddressException {
        final ClientOptions options = ClientOptions.builder().build();
        return newClient(options);
    }

    /**
     * Creates a new Workload API client configured with the given client options.
     * <p>
     * If the SPIFFE socket endpoint address is not provided in the options, it uses the default address.
     * {@link Address#getDefaultAddress()}
     *
     * @param options {@link ClientOptions}
     * @return a {@link WorkloadApiClient}, the instance concrete type is {@link DefaultWorkloadApiClient}
     * @throws SocketEndpointAddressException if the Workload API socket endpoint address is not valid
     */
    public static WorkloadApiClient newClient(ClientOptions options) throws SocketEndpointAddressException {
        Objects.requireNonNull(options, "options must not be null");

        final String spiffeSocketPath = StringUtils.isNotBlank(options.spiffeSocketPath)
                ? options.spiffeSocketPath
                : Address.getDefaultAddress();

        if (options.exponentialBackoffPolicy == null) {
            options.exponentialBackoffPolicy = ExponentialBackoffPolicy.DEFAULT;
        }

        if (options.executorService == null) {
            options.executorService = Executors.newCachedThreadPool();
        }

        final URI socketEndpointAddress = Address.parseAddress(spiffeSocketPath);
        final ManagedChannelWrapper managedChannel = GrpcManagedChannelFactory.newChannel(socketEndpointAddress, options.executorService);
        final SecurityHeaderInterceptor securityHeaderInterceptor = new SecurityHeaderInterceptor();
        final SpiffeWorkloadAPIStub workloadAPIAsyncStub = SpiffeWorkloadAPIGrpc
                .newStub(managedChannel.getChannel())
                .withExecutor(options.executorService)
                .withInterceptors(securityHeaderInterceptor);

        final SpiffeWorkloadAPIBlockingStub workloadAPIBlockingStub = SpiffeWorkloadAPIGrpc
                .newBlockingStub(managedChannel.getChannel())
                .withExecutor(options.executorService)
                .withInterceptors(securityHeaderInterceptor);

        final ScheduledExecutorService retryExecutor = Executors.newSingleThreadScheduledExecutor();

        return new DefaultWorkloadApiClient(
                workloadAPIAsyncStub,
                workloadAPIBlockingStub,
                managedChannel,
                options.exponentialBackoffPolicy,
                retryExecutor,
                options.executorService);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public X509Context fetchX509Context() throws X509ContextException {
        try (final Context.CancellableContext cancellableContext = Context.current().withCancellation()) {
            return cancellableContext.call(this::callFetchX509Context);
        } catch (Exception e) {
            throw new X509ContextException("Error fetching X509Context", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void watchX509Context(Watcher<X509Context> watcher) {
        Objects.requireNonNull(watcher, "watcher must not be null");

        final RetryHandler retryHandler = new RetryHandler(exponentialBackoffPolicy, retryExecutor);
        final Context.CancellableContext cancellableContext = Context.current().withCancellation();

        final StreamObserver<Workload.X509SVIDResponse> streamObserver =
                getX509ContextStreamObserver(watcher, retryHandler, cancellableContext, workloadApiAsyncStub);

        cancellableContext.run(() -> workloadApiAsyncStub.fetchX509SVID(newX509SvidRequest(), streamObserver));
        this.cancellableContexts.add(cancellableContext);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public X509BundleSet fetchX509Bundles() throws X509BundleException {
        try (final Context.CancellableContext cancellableContext = Context.current().withCancellation()) {
            return cancellableContext.call(this::callFetchX509Bundles);
        } catch (Exception e) {
            throw new X509BundleException("Error fetching X.509 bundles", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void watchX509Bundles(Watcher<X509BundleSet> watcher) {
        Objects.requireNonNull(watcher, "watcher must not be null");

        final RetryHandler retryHandler = new RetryHandler(exponentialBackoffPolicy, retryExecutor);
        final Context.CancellableContext cancellableContext = Context.current().withCancellation();

        final StreamObserver<Workload.X509BundlesResponse> streamObserver =
                getX509BundlesStreamObserver(watcher, retryHandler, cancellableContext, workloadApiAsyncStub);

        cancellableContext.run(() -> workloadApiAsyncStub.fetchX509Bundles(newX509BundlesRequest(), streamObserver));
        this.cancellableContexts.add(cancellableContext);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtSvid fetchJwtSvid(String audience, String... extraAudience) throws JwtSvidException {
        Objects.requireNonNull(audience, "audience must not be null");

        final Set<String> audParam = createAudienceSet(audience, extraAudience);
        try (final Context.CancellableContext cancellableContext = Context.current().withCancellation()) {
            return cancellableContext.call(() -> callFetchJwtSvid(audParam));
        } catch (Exception e) {
            throw new JwtSvidException("Error fetching JWT SVID", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtSvid fetchJwtSvid(SpiffeId subject,
                                String audience,
                                final String... extraAudience)
            throws JwtSvidException {

        Objects.requireNonNull(subject, "subject must not be null");
        Objects.requireNonNull(audience, "audience must not be null");

        final Set<String> audParam = createAudienceSet(audience, extraAudience);

        try (Context.CancellableContext cancellableContext = Context.current().withCancellation()) {
            return cancellableContext.call(() -> callFetchJwtSvid(subject, audParam));
        } catch (Exception e) {
            throw new JwtSvidException("Error fetching JWT SVID", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<JwtSvid> fetchJwtSvids(String audience, String... extraAudience) throws JwtSvidException {
        Objects.requireNonNull(audience, "audience must not be null");

        final Set<String> audParam = createAudienceSet(audience, extraAudience);
        try (final Context.CancellableContext cancellableContext = Context.current().withCancellation()) {
            return cancellableContext.call(() -> callFetchJwtSvids(audParam));
        } catch (Exception e) {
            throw new JwtSvidException("Error fetching JWT SVID", e);
        }
    }

    /**
     * {@inheritDoc}
     *
     * @return
     */
    @Override
    public List<JwtSvid> fetchJwtSvids(SpiffeId subject,
                                       String audience,
                                       final String... extraAudience)
            throws JwtSvidException {

        Objects.requireNonNull(subject, "subject must not be null");
        Objects.requireNonNull(audience, "audience must not be null");

        final Set<String> audParam = createAudienceSet(audience, extraAudience);

        try (final Context.CancellableContext cancellableContext = Context.current().withCancellation()) {
            return cancellableContext.call(() -> callFetchJwtSvids(subject, audParam));
        } catch (Exception e) {
            throw new JwtSvidException("Error fetching JWT SVID", e);
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public JwtBundleSet fetchJwtBundles() throws JwtBundleException {
        try (Context.CancellableContext cancellableContext = Context.current().withCancellation()) {
            return cancellableContext.call(this::callFetchBundles);
        } catch (Exception e) {
            throw new JwtBundleException("Error fetching JWT Bundles", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtSvid validateJwtSvid(String token, String audience)
            throws JwtSvidException {

        Objects.requireNonNull(token, "token must not be null");
        Objects.requireNonNull(audience, "audience must not be null");

        Objects.requireNonNull(token, "token must not be null");

        final Workload.ValidateJWTSVIDRequest request = createJwtSvidRequest(token, audience);

        Workload.ValidateJWTSVIDResponse response;
        try (final Context.CancellableContext cancellableContext = Context.current().withCancellation()) {
            response = cancellableContext.call(() -> workloadApiBlockingStub.validateJWTSVID(request));
        } catch (Exception e) {
            throw new JwtSvidException("Error validating JWT SVID", e);
        }

        if (response == null || StringUtils.isBlank(response.getSpiffeId())) {
            throw new JwtSvidException("Error validating JWT SVID. Empty response from Workload API");
        }
        return JwtSvid.parseInsecure(token, Collections.singleton(audience), EMPTY);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void watchJwtBundles(Watcher<JwtBundleSet> watcher) {
        Objects.requireNonNull(watcher, "watcher must not be null");

        RetryHandler retryHandler = new RetryHandler(exponentialBackoffPolicy, retryExecutor);
        Context.CancellableContext cancellableContext = Context.current().withCancellation();

        StreamObserver<Workload.JWTBundlesResponse> streamObserver = getJwtBundleStreamObserver(watcher, retryHandler, cancellableContext, workloadApiAsyncStub);

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
                for (Context.CancellableContext context : cancellableContexts) {
                    context.close();
                }

                if (managedChannel != null) {
                    managedChannel.close();
                }

                retryExecutor.shutdown();
                executorService.shutdown();
                closed = true;
            }
        }
        log.log(Level.INFO, "WorkloadAPI client is closed");
    }


    private X509Context callFetchX509Context() throws X509ContextException {
        Iterator<Workload.X509SVIDResponse> x509SvidResponse = workloadApiBlockingStub.fetchX509SVID(newX509SvidRequest());
        return GrpcConversionUtils.toX509Context(x509SvidResponse);
    }

    private X509BundleSet callFetchX509Bundles() throws X509BundleException {
        Iterator<Workload.X509BundlesResponse> x509BundlesResponse = workloadApiBlockingStub.fetchX509Bundles(newX509BundlesRequest());
        return GrpcConversionUtils.toX509BundleSet(x509BundlesResponse);
    }

    private JwtSvid callFetchJwtSvid(final SpiffeId subject, final Set<String> audience) throws JwtSvidException {
        Workload.JWTSVIDRequest jwtSvidRequest = Workload.JWTSVIDRequest.newBuilder()
                .setSpiffeId(subject.toString())
                .addAllAudience(audience)
                .build();
        Workload.JWTSVIDResponse response = workloadApiBlockingStub.fetchJWTSVID(jwtSvidRequest);
        return processJwtSvidResponse(response, audience, true).get(0);
    }

    private JwtSvid callFetchJwtSvid(final Set<String> audience) throws JwtSvidException {
        Workload.JWTSVIDRequest jwtSvidRequest = Workload.JWTSVIDRequest.newBuilder()
                .addAllAudience(audience)
                .build();
        Workload.JWTSVIDResponse response = workloadApiBlockingStub.fetchJWTSVID(jwtSvidRequest);
        return processJwtSvidResponse(response, audience, true).get(0);
    }

    private List<JwtSvid> callFetchJwtSvids(final SpiffeId subject, final Set<String> audience) throws JwtSvidException {
        Workload.JWTSVIDRequest jwtSvidRequest = Workload.JWTSVIDRequest.newBuilder()
                .setSpiffeId(subject.toString())
                .addAllAudience(audience)
                .build();
        Workload.JWTSVIDResponse response = workloadApiBlockingStub.fetchJWTSVID(jwtSvidRequest);
        return processJwtSvidResponse(response, audience, false);
    }

    private List<JwtSvid> callFetchJwtSvids(final Set<String> audience) throws JwtSvidException {
        Workload.JWTSVIDRequest jwtSvidRequest = Workload.JWTSVIDRequest.newBuilder()
                .addAllAudience(audience)
                .build();
        Workload.JWTSVIDResponse response = workloadApiBlockingStub.fetchJWTSVID(jwtSvidRequest);
        return processJwtSvidResponse(response, audience, false);
    }

    private List<JwtSvid> processJwtSvidResponse(Workload.JWTSVIDResponse response, Set<String> audience, boolean firstOnly) throws JwtSvidException {
        if (response.getSvidsList() == null || response.getSvidsList().isEmpty()) {
            throw new JwtSvidException("JWT SVID response from the Workload API is empty");
        }
        int n = response.getSvidsCount();
        if (firstOnly) {
            n = 1;
        }
        ArrayList<JwtSvid> svids = new ArrayList<>(n);
        HashSet<String> hints = new HashSet<>();
        for (int i = 0; i < n; i++) {
            // In the event of more than one JWTSVID message with the same hint value set, then the first message in the
            // list SHOULD be selected.
            if (hints.contains(response.getSvids(i).getHint())) {
                continue;
            }
            JwtSvid svid = JwtSvid.parseInsecure(response.getSvids(i).getSvid(), audience, response.getSvids(i).getHint());
            hints.add(svid.getHint());
            svids.add(svid);
        }
        return svids;
    }

    private JwtBundleSet callFetchBundles() throws JwtBundleException {
        Workload.JWTBundlesRequest request = Workload.JWTBundlesRequest.newBuilder().build();
        Iterator<Workload.JWTBundlesResponse> bundlesResponse = workloadApiBlockingStub.fetchJWTBundles(request);
        return GrpcConversionUtils.toJwtBundleSet(bundlesResponse);
    }

    private Set<String> createAudienceSet(final String audience, final String[] extraAudience) {
        final Set<String> audParam = new HashSet<>();
        audParam.add(audience);
        Collections.addAll(audParam, extraAudience);
        return audParam;
    }

    private Workload.X509SVIDRequest newX509SvidRequest() {
        return Workload.X509SVIDRequest.newBuilder().build();
    }

    private Workload.X509BundlesRequest newX509BundlesRequest() {
        return Workload.X509BundlesRequest.newBuilder().build();
    }

    private Workload.JWTBundlesRequest newJwtBundlesRequest() {
        return Workload.JWTBundlesRequest.newBuilder().build();
    }

    private Workload.ValidateJWTSVIDRequest createJwtSvidRequest(final String token, final String audience) {
        return Workload.ValidateJWTSVIDRequest
                .newBuilder()
                .setSvid(token)
                .setAudience(audience)
                .build();
    }

    /**
     * Options for creating a new {@link DefaultWorkloadApiClient}.
     * <p>
     * <code>spiffeSocketPath</code> Workload API Socket Endpoint address.
     * <p>
     * <code>backoffPolicy</code> A custom instance of a {@link ExponentialBackoffPolicy} to configure the retries to reconnect
     * to the Workload API.
     * <p>
     * <code>executorService</code> A custom {@link ExecutorService} to configure the Grpc stubs and channels.
     * If it is not provided, an <code>Executors.newCachedThreadPool()</code> is used by default.
     * The executorService provided will be shutdown when the WorkloadApiClient instance is closed.
     */
    public final static class ClientOptions {

        private String spiffeSocketPath;
        private ExponentialBackoffPolicy exponentialBackoffPolicy;
        private ExecutorService executorService;

        public ClientOptions(String spiffeSocketPath,
                             ExponentialBackoffPolicy exponentialBackoffPolicy,
                             ExecutorService executorService) {
            this.spiffeSocketPath = spiffeSocketPath;
            this.exponentialBackoffPolicy = exponentialBackoffPolicy;
            this.executorService = executorService;
        }

        public String getSpiffeSocketPath() {
            return spiffeSocketPath;
        }

        public ExponentialBackoffPolicy getExponentialBackoffPolicy() {
            return exponentialBackoffPolicy;
        }

        public ExecutorService getExecutorService() {
            return executorService;
        }

        public static Builder builder() {
            return new Builder();
        }

        public static final class Builder {
            private String spiffeSocketPath;
            private ExponentialBackoffPolicy exponentialBackoffPolicy;
            private ExecutorService executorService;

            public Builder spiffeSocketPath(String spiffeSocketPath) {
                this.spiffeSocketPath = spiffeSocketPath;
                return this;
            }

            public Builder exponentialBackoffPolicy(ExponentialBackoffPolicy exponentialBackoffPolicy) {
                this.exponentialBackoffPolicy = exponentialBackoffPolicy;
                return this;
            }

            public Builder executorService(ExecutorService executorService) {
                this.executorService = executorService;
                return this;
            }

            public ClientOptions build() {
                return new ClientOptions(
                        spiffeSocketPath,
                        exponentialBackoffPolicy,
                        executorService
                );
            }
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof ClientOptions)) return false;
            ClientOptions that = (ClientOptions) o;
            return Objects.equals(spiffeSocketPath, that.spiffeSocketPath)
                    && Objects.equals(exponentialBackoffPolicy, that.exponentialBackoffPolicy)
                    && Objects.equals(executorService, that.executorService);
        }

        @Override
        public int hashCode() {
            return Objects.hash(spiffeSocketPath, exponentialBackoffPolicy, executorService);
        }

        @Override
        public String toString() {
            return "ClientOptions{" +
                    "spiffeSocketPath='" + spiffeSocketPath + '\'' +
                    ", exponentialBackoffPolicy=" + exponentialBackoffPolicy +
                    ", executorService=" + executorService +
                    '}';
        }
    }
}
