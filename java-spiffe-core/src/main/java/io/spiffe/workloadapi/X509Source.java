package io.spiffe.workloadapi;

import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.exception.X509SourceException;
import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.extern.java.Log;
import lombok.val;
import org.apache.commons.lang3.exception.ExceptionUtils;
import io.spiffe.bundle.BundleSource;
import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.bundle.x509bundle.X509BundleSet;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.svid.x509svid.X509Svid;
import io.spiffe.svid.x509svid.X509SvidSource;

import java.io.Closeable;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;
import java.util.logging.Level;

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
@Log
public class X509Source implements X509SvidSource, BundleSource<X509Bundle>, Closeable {

    private static final String TIMEOUT_SYSTEM_PROPERTY = "spiffe.newX509Source.timeout";
    private static final Duration DEFAULT_TIMEOUT = Duration.parse(System.getProperty(TIMEOUT_SYSTEM_PROPERTY, "PT0S"));

    private X509Svid svid;
    private X509BundleSet bundles;

    private Function<List<X509Svid>, X509Svid> picker;
    private WorkloadApiClient workloadApiClient;
    private volatile boolean closed;

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
     * @return an instance of {@link X509Source}, with the svid and bundles initialized
     * @throws SocketEndpointAddressException if the address to the Workload API is not valid
     * @throws X509SourceException            if the source could not be initialized
     */
    public static X509Source newSource() throws SocketEndpointAddressException, X509SourceException {
        X509SourceOptions x509SourceOptions = X509SourceOptions.builder().initTimeout(DEFAULT_TIMEOUT).build();
        return newSource(x509SourceOptions);
    }

    /**
     * Creates a new X.509 source. It blocks until the initial update with the X.509 materials
     * has been received from the Workload API, doing retries with a backoff exponential policy,
     * or the timeout has expired.
     * <p>
     * If the timeout is not provided in the options, the default timeout is read from the
     * system property `spiffe.newX509Source.timeout`. If none is configured, this method will
     * block until the X.509 materials can be retrieved from the Workload API.
     * <p>
     * The {@link WorkloadApiClient} can be provided in the options, if it is not,
     * a new client is created.
     *
     * @param options {@link X509SourceOptions}
     * @return an instance of {@link X509Source}, with the svid and bundles initialized
     * @throws SocketEndpointAddressException if the address to the Workload API is not valid
     * @throws X509SourceException            if the source could not be initialized
     */
    public static X509Source newSource(@NonNull final X509SourceOptions options) throws SocketEndpointAddressException, X509SourceException {
        if (options.workloadApiClient == null) {
            options.workloadApiClient = createClient(options);
        }

        if (options.initTimeout == null) {
            options.initTimeout = DEFAULT_TIMEOUT;
        }

        val x509Source = new X509Source();
        x509Source.picker = options.picker;
        x509Source.workloadApiClient = options.workloadApiClient;

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
     *
     * @throws BundleNotFoundException is there is no bundle for the trust domain provided
     * @throws IllegalStateException if the source is closed
     */
    @Override
    public X509Bundle getBundleForTrustDomain(@NonNull final TrustDomain trustDomain) throws BundleNotFoundException {
        if (isClosed()) {
            throw new IllegalStateException("X.509 bundle source is closed");
        }
        return bundles.getBundleForTrustDomain(trustDomain);
    }

    /**
     * Closes this source, dropping the connection to the Workload API.
     * Other source methods will return an error after close has been called.
     */
    @Override
    public void close() {
        if (!closed) {
            synchronized (this) {
                if (!closed) {
                    workloadApiClient.close();
                    closed = true;
                }
            }
        }
    }

    // private constructor
    private X509Source() {
    }

    private static WorkloadApiClient createClient(@NonNull final X509SourceOptions options) throws SocketEndpointAddressException {
        val clientOptions = WorkloadApiClient.ClientOptions
                .builder()
                .spiffeSocketPath(options.spiffeSocketPath)
                .build();
        return WorkloadApiClient.newClient(clientOptions);
    }

    private void init(Duration timeout) throws TimeoutException {
        CountDownLatch done = new CountDownLatch(1);
        setX509ContextWatcher(done);

        boolean success;
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

    private void setX509ContextWatcher(CountDownLatch done) {
        workloadApiClient.watchX509Context(new Watcher<X509Context>() {
            @Override
            public void onUpdate(X509Context update) {
                log.log(Level.INFO, "Received X509Context update");
                setX509Context(update);
                done.countDown();
            }

            @Override
            public void onError(Throwable error) {
                log.log(Level.SEVERE, String.format("Error in X509Context watcher: %s", ExceptionUtils.getStackTrace(error)));
                done.countDown();
            }
        });
    }

    private void setX509Context(@NonNull final X509Context update) {
        X509Svid svidUpdate;
        if (picker == null) {
            svidUpdate = update.getDefaultSvid();
        } else {
            svidUpdate = picker.apply(update.getX509Svid());
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
     * Options for creating a new {@link X509Source}
     */
    @Data
    public static class X509SourceOptions {

        /**
         * Address to the Workload API, if it is not set, the default address will be used.
         */
        String spiffeSocketPath;

        /**
         * Timeout for initializing the {@link X509Source}.
         */
        Duration initTimeout;

        /**
         * Function to choose the X.509 SVID from the list returned by the Workload API
         * If it is not set, the default svid is picked.
         */
        Function<List<X509Svid>, X509Svid> picker;

        /**
         * A custom instance of a {@link WorkloadApiClient}, if it is not set, a new instance will be created
         */
        WorkloadApiClient workloadApiClient;

        @Builder
        public X509SourceOptions(String spiffeSocketPath,
                                 Duration initTimeout,
                                 Function<List<X509Svid>, X509Svid> picker,
                                 WorkloadApiClient workloadApiClient) {
            this.spiffeSocketPath = spiffeSocketPath;
            this.initTimeout = initTimeout;
            this.picker = picker;
            this.workloadApiClient = workloadApiClient;
        }
    }
}
