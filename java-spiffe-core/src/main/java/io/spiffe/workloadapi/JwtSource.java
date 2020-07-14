package io.spiffe.workloadapi;

import io.spiffe.bundle.BundleSource;
import io.spiffe.bundle.jwtbundle.JwtBundle;
import io.spiffe.bundle.jwtbundle.JwtBundleSet;
import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.exception.JwtSourceException;
import io.spiffe.exception.JwtSvidException;
import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.exception.WatcherException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.svid.jwtsvid.JwtSvid;
import io.spiffe.svid.jwtsvid.JwtSvidSource;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.Setter;
import lombok.SneakyThrows;
import lombok.extern.java.Log;
import lombok.val;

import java.io.Closeable;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;

import static io.spiffe.workloadapi.internal.ThreadUtils.await;

/**
 * Represents a source of SPIFFE JWT SVIDs and JWT bundles maintained via the Workload API.
 */
@Log
public class JwtSource implements JwtSvidSource, BundleSource<JwtBundle>, Closeable {

    static final String TIMEOUT_SYSTEM_PROPERTY = "spiffe.newJwtSource.timeout";

    static final Duration DEFAULT_TIMEOUT =
            Duration.parse(System.getProperty(TIMEOUT_SYSTEM_PROPERTY, "PT0S"));

    private JwtBundleSet bundles;

    private final WorkloadApiClient workloadApiClient;
    private volatile boolean closed;

    // private constructor
    private JwtSource(final WorkloadApiClient workloadApiClient) {
        this.workloadApiClient = workloadApiClient;
    }

    /**
     * Creates a new JWT source. It blocks until the initial update with the JWT bundles
     * has been received from the Workload API or until the timeout configured
     * through the system property `spiffe.newJwtSource.timeout` expires.
     * If no timeout is configured, it blocks until it gets a JWT update from the Workload API.
     * <p>
     * It uses the default address socket endpoint from the environment variable to get the Workload API address.
     *
     * @return an instance of {@link JwtSource}, with the JWT bundles initialized
     * @throws SocketEndpointAddressException if the address to the Workload API is not valid
     * @throws JwtSourceException            if the source could not be initialized
     */
    public static JwtSource newSource() throws JwtSourceException, SocketEndpointAddressException {
        JwtSourceOptions options = JwtSourceOptions.builder().initTimeout(DEFAULT_TIMEOUT).build();
        return newSource(options);
    }

    /**
     * Creates a new JWT source. It blocks until the initial update with the JWT bundles
     * has been received from the Workload API, doing retries with a backoff exponential policy,
     * or until the initTimeout has expired.
     * <p>
     * If the timeout is not provided in the options, the default timeout is read from the
     * system property `spiffe.newJwtSource.timeout`. If none is configured, this method will
     * block until the JWT bundles can be retrieved from the Workload API.
     * <p>
     * The {@link WorkloadApiClient} can be provided in the options, if it is not,
     * a new client is created.
     *
     * @param options {@link JwtSourceOptions}
     * @return an instance of {@link JwtSource}, with the JWT bundles initialized
     * @throws SocketEndpointAddressException if the address to the Workload API is not valid
     * @throws JwtSourceException if the source could not be initialized
     */
    public static JwtSource newSource(@NonNull final JwtSourceOptions options)
            throws SocketEndpointAddressException, JwtSourceException {
        if (options.workloadApiClient == null) {
            options.workloadApiClient = createClient(options);
        }

        if (options.initTimeout == null) {
            options.initTimeout = DEFAULT_TIMEOUT;
        }

        JwtSource jwtSource = new JwtSource(options.workloadApiClient);

        try {
            jwtSource.init(options.initTimeout);
        } catch (Exception e) {
            jwtSource.close();
            throw new JwtSourceException("Error creating JWT source", e);
        }

        return jwtSource;
    }

    @Override
    public JwtSvid fetchJwtSvid(String audience, String... extraAudiences) throws JwtSvidException {
        if (isClosed()) {
            throw new IllegalStateException("JWT SVID source is closed");
        }
        return workloadApiClient.fetchJwtSvid(audience, extraAudiences);
    }

    /**
     * Fetches a new JWT SVID from the Workload API for the given subject SPIFFE ID and audiences.
     *
     * @return a {@link JwtSvid}
     * @throws IllegalStateException if the source is closed
     */
    @Override
    public JwtSvid fetchJwtSvid(final SpiffeId subject, final String audience, final String... extraAudiences)
            throws JwtSvidException {
        if (isClosed()) {
            throw new IllegalStateException("JWT SVID source is closed");
        }

        return workloadApiClient.fetchJwtSvid(subject, audience, extraAudiences);
    }

    /**
     * Returns the JWT bundle for a given trust domain.
     *
     * @return an instance of a {@link X509Bundle}
     *
     * @throws BundleNotFoundException is there is no bundle for the trust domain provided
     * @throws IllegalStateException if the source is closed
     */
    @Override
    public JwtBundle getBundleForTrustDomain(@NonNull final TrustDomain trustDomain) throws BundleNotFoundException {
        if (isClosed()) {
            throw new IllegalStateException("JWT bundle source is closed");
        }
        return bundles.getBundleForTrustDomain(trustDomain);
    }

    /**
     * Closes this source, dropping the connection to the Workload API.
     * Other source methods will return an error after close has been called.
     * <p>
     * It is marked with {@link SneakyThrows} because it is not expected to throw
     * the checked exception defined on the {@link Closeable} interface.
     */
    @SneakyThrows
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

    private void init(final Duration timeout) throws TimeoutException {
        CountDownLatch done = new CountDownLatch(1);
        setJwtBundlesWatcher(done);

        boolean success;
        if (timeout.isZero()) {
            await(done);
            success = true;
        } else {
            success = await(done, timeout.getSeconds(), TimeUnit.SECONDS);
        }
        if (!success) {
            throw new TimeoutException("Timeout waiting for JWT bundles update");
        }
    }

    private void setJwtBundlesWatcher(final CountDownLatch done) {
        workloadApiClient.watchJwtBundles(new Watcher<JwtBundleSet>() {
            @Override
            public void onUpdate(final JwtBundleSet update) {
                log.log(Level.INFO, "Received JwtBundleSet update");
                setJwtBundleSet(update);
                done.countDown();
            }

            @Override
            public void onError(final Throwable error) {
                log.log(Level.SEVERE, "Error in JwtBundleSet watcher", error);
                done.countDown();
                throw new WatcherException("Error fetching JwtBundleSet", error);
            }
        });
    }

    private void setJwtBundleSet(final JwtBundleSet update) {
        synchronized (this) {
            this.bundles = update;
        }
    }

    private boolean isClosed() {
        synchronized (this) {
            return closed;
        }
    }

    private static WorkloadApiClient createClient(final JwtSourceOptions options)
            throws SocketEndpointAddressException {
        val clientOptions = DefaultWorkloadApiClient.ClientOptions
                .builder()
                .spiffeSocketPath(options.spiffeSocketPath)
                .build();
        return DefaultWorkloadApiClient.newClient(clientOptions);
    }

    /**
     * Options to configure a {@link JwtSource}.
     * <p>
     * <code>spiffeSocketPath</code> Address to the Workload API, if it is not set, the default address will be used.
     * <p>
     * <code>initTimeout</code> Timeout for initializing the instance. If it is not defined, the timeout is read
     * from the System property `spiffe.newJwtSource.timeout'. If this is also not defined, no default timeout is applied.
     * <p>
     * <code>workloadApiClient</code> A custom instance of a {@link WorkloadApiClient}, if it is not set,
     * a new client will be created.
     */
    @Data
    public static class JwtSourceOptions {

        @Setter(AccessLevel.NONE)
        private String spiffeSocketPath;

        @Setter(AccessLevel.NONE)
        private Duration initTimeout;

        @Setter(AccessLevel.NONE)
        private WorkloadApiClient workloadApiClient;

        @Builder
        public JwtSourceOptions(
                final String spiffeSocketPath,
                final WorkloadApiClient workloadApiClient,
                final Duration initTimeout) {
            this.spiffeSocketPath = spiffeSocketPath;
            this.workloadApiClient = workloadApiClient;
            this.initTimeout = initTimeout;
        }
    }
}
