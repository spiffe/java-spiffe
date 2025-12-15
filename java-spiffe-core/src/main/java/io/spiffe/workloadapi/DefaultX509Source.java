package io.spiffe.workloadapi;

import io.spiffe.bundle.BundleSource;
import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.bundle.x509bundle.X509BundleSet;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.exception.WatcherException;
import io.spiffe.exception.X509SourceException;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.svid.x509svid.X509Svid;
import io.spiffe.svid.x509svid.X509SvidSource;

import java.io.Closeable;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import static io.spiffe.workloadapi.internal.ThreadUtils.await;

/**
 * Represents a source of X.509 SVIDs and X.509 bundles maintained via the Workload API.
 * <p>
 * It handles a {@link X509Svid} and a {@link X509BundleSet} that are updated automatically
 * whenever there is an update from the Workload API.
 * <p>
 * Implements {@link X509SvidSource} and {@link BundleSource}.
 * <p>
 * Implements the {@link Closeable} interface. The {@link #close()} method closes the source,
 * dropping the connection to the Workload API. Other source methods will return an error
 * after close has been called.
 */
public final class DefaultX509Source implements X509Source {

    private static final Logger log =
            Logger.getLogger(DefaultX509Source.class.getName());

    private static final String TIMEOUT_SYSTEM_PROPERTY = "spiffe.newX509Source.timeout";
    private static final Duration DEFAULT_TIMEOUT = Duration.parse(System.getProperty(TIMEOUT_SYSTEM_PROPERTY, "PT0S"));

    private X509Svid svid;
    private X509BundleSet bundles;

    private final Function<List<X509Svid>, X509Svid> picker;
    private final WorkloadApiClient workloadApiClient;

    private volatile boolean closed;

    // private constructor
    private DefaultX509Source(final Function<List<X509Svid>, X509Svid> svidPicker, final WorkloadApiClient workloadApiClient) {
        this.picker = svidPicker;
        this.workloadApiClient = workloadApiClient;
    }

    /**
     * Creates a new X.509 source. It blocks until the initial update with the X.509 materials
     * has been received from the Workload API or until the timeout configured
     * through the system property `spiffe.newX509Source.timeout` expires.
     * If no timeout is configured, it blocks until it gets an X.509 update from the Workload API.
     * <p>
     * It uses the default address socket endpoint from the environment variable to get the Workload API address.
     * <p>
     * It uses the default X.509 SVID (picks the first SVID that comes in the Workload API response).
     *
     * @return an instance of {@link DefaultX509Source}, with the SVID and bundles initialized
     * @throws SocketEndpointAddressException if the address to the Workload API is not valid
     * @throws X509SourceException            if the source could not be initialized
     */
    public static DefaultX509Source newSource() throws SocketEndpointAddressException, X509SourceException {
        X509SourceOptions x509SourceOptions = X509SourceOptions.builder().initTimeout(DEFAULT_TIMEOUT).build();
        return newSource(x509SourceOptions);
    }

    /**
     * Creates a new X.509 source. It blocks until the initial update with the X.509 materials
     * has been received from the Workload API, doing retries with a backoff exponential policy,
     * or until the timeout has expired.
     * <p>
     * If the timeout is not provided in the options, the default timeout is read from the
     * system property `spiffe.newX509Source.timeout`. If none is configured, this method will
     * block until the X.509 materials can be retrieved from the Workload API.
     * <p>
     * The {@link WorkloadApiClient} can be provided in the options, if it is not,
     * a new client is created.
     * <p>
     * If no SVID Picker is provided in the options, it uses the default X.509 SVID (picks the first SVID that comes
     * in the Workload API response).
     *
     * @param options {@link X509SourceOptions}
     * @return an instance of {@link DefaultX509Source}, with the SVID and bundles initialized
     * @throws SocketEndpointAddressException if the address to the Workload API is not valid
     * @throws X509SourceException            if the source could not be initialized
     */
    public static DefaultX509Source newSource(X509SourceOptions options)
            throws SocketEndpointAddressException, X509SourceException {
        Objects.requireNonNull(options, "options must not be null");

        if (options.workloadApiClient == null) {
            options.workloadApiClient = createClient(options);
        }

        if (options.initTimeout == null) {
            options.initTimeout = DEFAULT_TIMEOUT;
        }

        DefaultX509Source x509Source = new DefaultX509Source(options.svidPicker, options.workloadApiClient);

        try {
            x509Source.init(options.initTimeout);
        } catch (Exception e) {
            x509Source.close();
            throw new X509SourceException("Error creating X.509 source", e);
        }

        return x509Source;
    }

    /**
     * Returns the X.509 SVID handled by this source.
     *
     * @return a {@link X509Svid}
     * @throws IllegalStateException if the source is closed
     */
    @Override
    public X509Svid getX509Svid() {
        if (isClosed()) {
            throw new IllegalStateException("X.509 SVID source is closed");
        }
        return svid;
    }

    /**
     * Returns the X.509 bundle for a given trust domain.
     *
     * @return an instance of a {@link X509Bundle}
     * @throws BundleNotFoundException is there is no bundle for the trust domain provided
     * @throws IllegalStateException   if the source is closed
     */
    @Override
    public X509Bundle getBundleForTrustDomain(TrustDomain trustDomain) throws BundleNotFoundException {
        if (isClosed()) {
            throw new IllegalStateException("X.509 bundle source is closed");
        }
        return bundles.getBundleForTrustDomain(trustDomain);
    }

    /**
     * Closes this source, dropping the connection to the Workload API.
     * Other source methods will return an error after close has been called.
     * <p>
     */
    @Override
    public void close() {
        if (!closed) {
            synchronized (this) {
                if (!closed) {
                    try {
                        workloadApiClient.close();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                    closed = true;
                }
            }
        }
    }

    private static WorkloadApiClient createClient(final X509SourceOptions options)
            throws SocketEndpointAddressException {
        DefaultWorkloadApiClient.ClientOptions clientOptions = DefaultWorkloadApiClient.ClientOptions
                .builder()
                .spiffeSocketPath(options.spiffeSocketPath)
                .build();
        return DefaultWorkloadApiClient.newClient(clientOptions);
    }

    private void init(final Duration timeout) throws TimeoutException {
        CountDownLatch done = new CountDownLatch(1);
        setX509ContextWatcher(done);

        final boolean success;
        if (timeout.isZero()) {
            await(done);
            success = true;
        } else {
            success = await(done, timeout.getSeconds(), TimeUnit.SECONDS);
        }
        if (!success) {
            throw new TimeoutException("Timeout waiting for X.509 Context update");
        }
    }

    private void setX509ContextWatcher(final CountDownLatch done) {
        workloadApiClient.watchX509Context(new Watcher<X509Context>() {
            @Override
            public void onUpdate(final X509Context update) {
                String spiffeIds = update.getX509Svids().stream().map(s -> s.getSpiffeId().toString()).collect(Collectors.joining(", "));
                log.log(Level.INFO, String.format("Received X509Context update: %s", spiffeIds));
                setX509Context(update);
                done.countDown();
            }

            @Override
            public void onError(final Throwable error) {
                log.log(Level.SEVERE, "Error in X509Context watcher", error);
                done.countDown();
                throw new WatcherException("Error in X509Context watcher", error);
            }
        });
    }

    private void setX509Context(final X509Context update) {
        final X509Svid svidUpdate;
        if (picker == null) {
            svidUpdate = update.getDefaultSvid();
        } else {
            svidUpdate = picker.apply(update.getX509Svids());
        }
        synchronized (this) {
            this.svid = svidUpdate;
            this.bundles = update.getX509BundleSet();
        }
    }

    private boolean isClosed() {
        synchronized (this) {
            return closed;
        }
    }

    /**
     * Options for creating a new {@link DefaultX509Source}
     * <p>
     * <code>spiffeSocketPath</code> Address to the Workload API, if it is not set, the default address will be used.
     * <p>
     * <code>initTimeout</code> Timeout for initializing the instance. If it is not defined, the timeout is read
     * from the System property `spiffe.newX509Source.timeout'. If this is also not defined, no default timeout is applied.
     * <p>
     * <code>svidPicker</code>  Function to choose the X.509 SVID from the list returned by the Workload API.
     * If it is not set, the default SVID is picked.
     * <p>
     * <code>workloadApiClient</code> A custom instance of a {@link WorkloadApiClient}, if it is not set, a new client
     * will be created.
     */
    public static class X509SourceOptions {

        private String spiffeSocketPath;
        private Duration initTimeout;
        private Function<List<X509Svid>, X509Svid> svidPicker;
        private WorkloadApiClient workloadApiClient;

        public X509SourceOptions(String spiffeSocketPath,
                                 Duration initTimeout,
                                 Function<List<X509Svid>, X509Svid> svidPicker,
                                 WorkloadApiClient workloadApiClient) {
            this.spiffeSocketPath = spiffeSocketPath;
            this.initTimeout = initTimeout;
            this.svidPicker = svidPicker;
            this.workloadApiClient = workloadApiClient;
        }

        public String getSpiffeSocketPath() {
            return spiffeSocketPath;
        }

        public Duration getInitTimeout() {
            return initTimeout;
        }

        public Function<List<X509Svid>, X509Svid> getSvidPicker() {
            return svidPicker;
        }

        public WorkloadApiClient getWorkloadApiClient() {
            return workloadApiClient;
        }

        public void setSpiffeSocketPath(String spiffeSocketPath) {
            this.spiffeSocketPath = spiffeSocketPath;
        }

        public void setInitTimeout(Duration initTimeout) {
            this.initTimeout = initTimeout;
        }

        public void setSvidPicker(Function<List<X509Svid>, X509Svid> svidPicker) {
            this.svidPicker = svidPicker;
        }

        public void setWorkloadApiClient(WorkloadApiClient workloadApiClient) {
            this.workloadApiClient = workloadApiClient;
        }

        public static Builder builder() {
            return new Builder();
        }

        public static final class Builder {
            private String spiffeSocketPath;
            private Duration initTimeout;
            private Function<List<X509Svid>, X509Svid> svidPicker;
            private WorkloadApiClient workloadApiClient;

            public Builder spiffeSocketPath(String spiffeSocketPath) {
                this.spiffeSocketPath = spiffeSocketPath;
                return this;
            }

            public Builder initTimeout(Duration initTimeout) {
                this.initTimeout = initTimeout;
                return this;
            }

            public Builder svidPicker(Function<List<X509Svid>, X509Svid> svidPicker) {
                this.svidPicker = svidPicker;
                return this;
            }

            public Builder workloadApiClient(WorkloadApiClient workloadApiClient) {
                this.workloadApiClient = workloadApiClient;
                return this;
            }

            public X509SourceOptions build() {
                return new X509SourceOptions(
                        spiffeSocketPath,
                        initTimeout,
                        svidPicker,
                        workloadApiClient
                );
            }
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof X509SourceOptions)) return false;
            X509SourceOptions that = (X509SourceOptions) o;
            return Objects.equals(spiffeSocketPath, that.spiffeSocketPath) &&
                    Objects.equals(initTimeout, that.initTimeout) &&
                    Objects.equals(svidPicker, that.svidPicker) &&
                    Objects.equals(workloadApiClient, that.workloadApiClient);
        }

        @Override
        public int hashCode() {
            return Objects.hash(spiffeSocketPath, initTimeout, svidPicker, workloadApiClient);
        }

        @Override
        public String toString() {
            return "X509SourceOptions(" +
                    "spiffeSocketPath='" + spiffeSocketPath + '\'' +
                    ", initTimeout=" + initTimeout +
                    ", svidPicker=" + svidPicker +
                    ", workloadApiClient=" + workloadApiClient +
                    ')';
        }
    }
}
