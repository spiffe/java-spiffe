package io.spiffe.workloadapi;

import io.spiffe.bundle.jwtbundle.JwtBundle;
import io.spiffe.bundle.jwtbundle.JwtBundleSet;
import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.exception.*;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.svid.jwtsvid.JwtSvid;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;

import static io.spiffe.workloadapi.internal.ThreadUtils.await;

/**
 * Represents a source of SPIFFE JWT SVIDs and JWT bundles maintained via the Workload API.
 */
public class DefaultJwtSource implements JwtSource {

    private static final Logger log =
            Logger.getLogger(DefaultJwtSource.class.getName());

    static final String TIMEOUT_SYSTEM_PROPERTY = "spiffe.newJwtSource.timeout";

    static final Duration DEFAULT_TIMEOUT =
            Duration.parse(System.getProperty(TIMEOUT_SYSTEM_PROPERTY, "PT0S"));

    private JwtBundleSet bundles;

    private final WorkloadApiClient workloadApiClient;
    private volatile boolean closed;

    // private constructor
    private DefaultJwtSource(final WorkloadApiClient workloadApiClient) {
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
     * @return an instance of {@link DefaultJwtSource}, with the JWT bundles initialized
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
     * @return an instance of {@link DefaultJwtSource}, with the JWT bundles initialized
     * @throws SocketEndpointAddressException if the address to the Workload API is not valid
     * @throws JwtSourceException if the source could not be initialized
     */
    public static JwtSource newSource(JwtSourceOptions options)
            throws SocketEndpointAddressException, JwtSourceException {
        Objects.requireNonNull(options, "options must not be null");

        if (options.getWorkloadApiClient()== null) {
            options.setWorkloadApiClient(createClient(options));
        }

        if (options.getInitTimeout()== null) {
            options.setInitTimeout(DEFAULT_TIMEOUT);
        }

        DefaultJwtSource jwtSource = new DefaultJwtSource(options.getWorkloadApiClient());

        try {
            jwtSource.init(options.getInitTimeout());
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

    @Override
    public List<JwtSvid> fetchJwtSvids(String audience, String... extraAudiences) throws JwtSvidException {
        if (isClosed()) {
            throw new IllegalStateException("JWT SVID source is closed");
        }
        return workloadApiClient.fetchJwtSvids(audience, extraAudiences);
    }

    /**
     * Fetches all new JWT SVIDs from the Workload API for the given subject SPIFFE ID and audiences.
     *
     * @return all {@link JwtSvid}s
     * @throws IllegalStateException if the source is closed
     */
    @Override
    public List<JwtSvid> fetchJwtSvids(final SpiffeId subject, final String audience, final String... extraAudiences)
            throws JwtSvidException {
        if (isClosed()) {
            throw new IllegalStateException("JWT SVID source is closed");
        }

        return workloadApiClient.fetchJwtSvids(subject, audience, extraAudiences);
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

    private static WorkloadApiClient createClient(JwtSourceOptions options)
            throws SocketEndpointAddressException {
        DefaultWorkloadApiClient.ClientOptions clientOptions = DefaultWorkloadApiClient.ClientOptions
                .builder()
                .spiffeSocketPath(options.getSpiffeSocketPath())
                .build();
        return DefaultWorkloadApiClient.newClient(clientOptions);
    }
}
