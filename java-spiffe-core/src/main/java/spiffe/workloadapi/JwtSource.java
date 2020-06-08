package spiffe.workloadapi;

import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.extern.java.Log;
import lombok.val;
import org.apache.commons.lang3.exception.ExceptionUtils;
import spiffe.bundle.BundleSource;
import spiffe.bundle.jwtbundle.JwtBundle;
import spiffe.bundle.jwtbundle.JwtBundleSet;
import spiffe.bundle.x509bundle.X509Bundle;
import spiffe.exception.BundleNotFoundException;
import spiffe.exception.JwtSourceException;
import spiffe.exception.JwtSvidException;
import spiffe.exception.SocketEndpointAddressException;
import spiffe.spiffeid.SpiffeId;
import spiffe.spiffeid.TrustDomain;
import spiffe.svid.jwtsvid.JwtSvid;
import spiffe.svid.jwtsvid.JwtSvidSource;

import java.io.Closeable;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;

import static spiffe.workloadapi.internal.ThreadUtils.await;

/**
 * A <code>JwtSource</code> represents a source of SPIFFE JWT SVID and JWT bundles
 * maintained via the Workload API.
 */
@Log
public class JwtSource implements JwtSvidSource, BundleSource<JwtBundle>, Closeable {

    private static final Duration DEFAULT_TIMEOUT;

    static {
        DEFAULT_TIMEOUT = Duration.ofSeconds(Long.getLong("spiffe.newJwtSource.timeout", 0));
    }

    private JwtBundleSet bundles;
    private WorkloadApiClient workloadApiClient;
    private volatile boolean closed;

    /**
     * Creates a new JWT source. It blocks until the initial update
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
        JwtSourceOptions options = JwtSourceOptions.builder().build();
        return newSource(options, DEFAULT_TIMEOUT);
    }

    /**
     * Creates a new JWT source. It blocks until the initial update
     * has been received from the Workload API or until the timeout configured
     * through the system property `spiffe.newJwtSource.timeout` expires.
     * If no timeout is configured, it blocks until it gets a JWT update from the Workload API.
     * <p>
     * It uses the default address socket endpoint from the environment variable to get the Workload API address.
     *
     * @param timeout Time to wait for the JWT bundles update. If the timeout is Zero, it will wait indefinitely.
     * @return an instance of {@link JwtSource}, with the JWT bundles initialized
     * @throws SocketEndpointAddressException if the address to the Workload API is not valid
     * @throws JwtSourceException            if the source could not be initialized
     */
    public static JwtSource newSource(@NonNull Duration timeout) throws JwtSourceException, SocketEndpointAddressException {
        JwtSourceOptions options = JwtSourceOptions.builder().build();
        return newSource(options, timeout);
    }

    /**
     * Creates a new JWT source. It blocks until the initial update
     * has been received from the Workload API or until the timeout configured
     * through the system property `spiffe.newJwtSource.timeout` expires.
     * If no timeout is configured, it blocks until it gets a JWT update from the Workload API.
     * <p>
     * It uses the default address socket endpoint from the environment variable to get the Workload API address.
     *
     * @param options {@link JwtSourceOptions}
     * @return an instance of {@link JwtSource}, with the JWT bundles initialized
     * @throws SocketEndpointAddressException if the address to the Workload API is not valid
     * @throws JwtSourceException            if the source could not be initialized
     */
    public static JwtSource newSource(@NonNull JwtSourceOptions options) throws JwtSourceException, SocketEndpointAddressException {
        return newSource(options, DEFAULT_TIMEOUT);
    }


    /**
     * Creates a new JWT source. It blocks until the initial update
     * has been received from the Workload API, doing retries with a backoff exponential policy,
     * or the timeout has expired.
     * <p>
     * The {@link WorkloadApiClient} can be provided in the options, if it is not,
     * a new client is created.
     *
     * @param timeout Time to wait for the JWT bundles update. If the timeout is Zero, it will wait indefinitely.
     * @param options {@link JwtSourceOptions}
     * @return an instance of {@link JwtSource}, with the JWT bundles initialized
     * @throws SocketEndpointAddressException if the address to the Workload API is not valid
     * @throws JwtSourceException if the source could not be initialized
     */
    public static JwtSource newSource(@NonNull JwtSourceOptions options, @NonNull Duration timeout) throws SocketEndpointAddressException, JwtSourceException {
        if (options.workloadApiClient == null) {
            options.workloadApiClient = createClient(options);
        }

        JwtSource jwtSource = new JwtSource();
        jwtSource.workloadApiClient = options.workloadApiClient;

        try {
            jwtSource.init(timeout);
        } catch (Exception e) {
            jwtSource.close();
            throw new JwtSourceException("Error creating JWT source", e);
        }

        return jwtSource;
    }

    /**
     * Returns the JWT SVID handled by this source.
     *
     * @return a {@link JwtSvid}
     * @throws IllegalStateException if the source is closed
     */
    @Override
    public JwtSvid fetchJwtSvid(SpiffeId subject, String audience, String... extraAudiences) throws JwtSvidException {
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
    public JwtBundle getBundleForTrustDomain(TrustDomain trustDomain) throws BundleNotFoundException {
        if (isClosed()) {
            throw new IllegalStateException("JWT bundle source is closed");
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


    private void init(Duration timeout) throws TimeoutException {
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

    private void setJwtBundlesWatcher(CountDownLatch done) {
        workloadApiClient.watchJwtBundles(new Watcher<JwtBundleSet>() {
            @Override
            public void onUpdate(JwtBundleSet update) {
                log.log(Level.INFO, "Received JwtBundleSet update");
                setJwtBundleSet(update);
                done.countDown();
            }

            @Override
            public void onError(Throwable error) {
                log.log(Level.SEVERE, String.format("Error in JwtBundleSet watcher: %s", ExceptionUtils.getStackTrace(error)));
                done.countDown();
            }
        });
    }

    private void setJwtBundleSet(@NonNull final JwtBundleSet update) {
        synchronized (this) {
            this.bundles = update;
        }
    }

    private boolean isClosed() {
        synchronized (this) {
            return closed;
        }
    }

    private static WorkloadApiClient createClient(@NonNull JwtSourceOptions options) throws SocketEndpointAddressException {
        val clientOptions = WorkloadApiClient.ClientOptions
                .builder()
                .spiffeSocketPath(options.spiffeSocketPath)
                .build();
        return WorkloadApiClient.newClient(clientOptions);
    }

    // private constructor
    private JwtSource() {
    }

    @Data
    public static class JwtSourceOptions {

        /**
         * Address to the Workload API, if it is not set, the default address will be used.
         */
        String spiffeSocketPath;

        /**
         * A custom instance of a {@link WorkloadApiClient}, if it is not set, a new instance will be created.
         */
        WorkloadApiClient workloadApiClient;

        @Builder
        public JwtSourceOptions(String spiffeSocketPath, WorkloadApiClient workloadApiClient) {
            this.spiffeSocketPath = spiffeSocketPath;
            this.workloadApiClient = workloadApiClient;
        }
    }
}
