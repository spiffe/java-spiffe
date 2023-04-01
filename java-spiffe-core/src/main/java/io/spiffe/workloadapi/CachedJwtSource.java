package io.spiffe.workloadapi;


import io.spiffe.bundle.jwtbundle.JwtBundle;
import io.spiffe.bundle.jwtbundle.JwtBundleSet;
import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.exception.*;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.svid.jwtsvid.JwtSvid;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.java.Log;
import lombok.val;
import org.apache.commons.lang3.tuple.ImmutablePair;

import java.io.Closeable;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;

import static io.spiffe.workloadapi.internal.ThreadUtils.await;

/**
 * Represents a source of SPIFFE JWT SVIDs and JWT bundles maintained via the Workload API.
 * The JWT SVIDs are cached and fetchJwtSvid methods return from cache
 * checking that the JWT SVID has still at least half of its lifetime.
 */
@Log
public class CachedJwtSource implements JwtSource {
    static final String TIMEOUT_SYSTEM_PROPERTY = "spiffe.newJwtSource.timeout";

    static final Duration DEFAULT_TIMEOUT =
            Duration.parse(System.getProperty(TIMEOUT_SYSTEM_PROPERTY, "PT0S"));

    // Synchronized map of JWT SVIDs, keyed by a pair of SPIFFE ID and a Set of audiences strings.
    // This map is used to cache the JWT SVIDs and avoid fetching them from the Workload API.
    private final
    Map<ImmutablePair<SpiffeId, Set<String>>, List<JwtSvid>> jwtSvids = new ConcurrentHashMap<>();

    private JwtBundleSet bundles;

    private final WorkloadApiClient workloadApiClient;
    private volatile boolean closed;
    private Clock clock;

    // private constructor
    private CachedJwtSource(final WorkloadApiClient workloadApiClient) {
        this.clock = Clock.systemDefaultZone();
        this.workloadApiClient = workloadApiClient;
    }

    /**
     * Creates a new Cached JWT source. It blocks until the initial update with the JWT bundles
     * has been received from the Workload API or until the timeout configured
     * through the system property `spiffe.newJwtSource.timeout` expires.
     * If no timeout is configured, it blocks until it gets a JWT update from the Workload API.
     * <p>
     * It uses the default address socket endpoint from the environment variable to get the Workload API address.
     *
     * @return an instance of {@link DefaultJwtSource}, with the JWT bundles initialized
     * @throws SocketEndpointAddressException if the address to the Workload API is not valid
     * @throws JwtSourceException             if the source could not be initialized
     */
    public static JwtSource newSource() throws JwtSourceException, SocketEndpointAddressException {
        JwtSourceOptions options = JwtSourceOptions.builder().initTimeout(DEFAULT_TIMEOUT).build();
        return newSource(options);
    }

    /**
     * Creates a new JWT source. It blocks until the initial update with the JWT bundles
     * has been received from the Workload API, doing retries with an exponential backoff policy,
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
     * @return an instance of {@link CachedJwtSource}, with the JWT bundles initialized
     * @throws SocketEndpointAddressException if the address to the Workload API is not valid
     * @throws JwtSourceException             if the source could not be initialized
     */
    public static JwtSource newSource(@NonNull final JwtSourceOptions options)
            throws SocketEndpointAddressException, JwtSourceException {
        if (options.getWorkloadApiClient() == null) {
            options.setWorkloadApiClient(createClient(options));
        }

        if (options.getInitTimeout() == null) {
            options.setInitTimeout(DEFAULT_TIMEOUT);
        }

        CachedJwtSource jwtSource = new CachedJwtSource(options.getWorkloadApiClient());

        try {
            jwtSource.init(options.getInitTimeout());
        } catch (Exception e) {
            jwtSource.close();
            throw new JwtSourceException("Error creating JWT source", e);
        }

        return jwtSource;
    }

    /**
     * Fetches a JWT SVID for the given audiences. The JWT SVID is cached and
     * returned from the cache if it still has at least half of its lifetime.
     *
     * @param audience       the audience
     * @param extraAudiences a list of extra audiences as an array of String
     * @return a {@link JwtSvid}
     * @throws JwtSvidException
     */
    @Override
    public JwtSvid fetchJwtSvid(String audience, String... extraAudiences) throws JwtSvidException {
        if (isClosed()) {
            throw new IllegalStateException("JWT SVID source is closed");
        }

        return getJwtSvids(null, audience, extraAudiences).get(0);
    }

    /**
     * Fetches a JWT SVID for the given subject and audience. The JWT SVID is cached and
     * returned from cache if it has still at least half of its lifetime.
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

        return getJwtSvids(subject, audience, extraAudiences).get(0);
    }

    /**
     * Fetches a list of JWT SVIDs for the given audience. The JWT SVIDs are cached and
     * returned from cache if they have still at least half of their lifetime.
     *
     * @return a list of {@link JwtSvid}s
     * @throws IllegalStateException if the source is closed
     */
    @Override
    public List<JwtSvid> fetchJwtSvids(String audience, String... extraAudiences) throws JwtSvidException {
        if (isClosed()) {
            throw new IllegalStateException("JWT SVID source is closed");
        }

        return getJwtSvids(null, audience, extraAudiences);
    }

    /**
     * Fetches a list of JWT SVIDs for the given subject and audience. The JWT SVIDs are cached and
     * returned from cache if they have still at least half of their lifetime.
     *
     * @return a list of {@link JwtSvid}s
     * @throws IllegalStateException if the source is closed
     */
    @Override
    public List<JwtSvid> fetchJwtSvids(final SpiffeId subject, final String audience, final String... extraAudiences)
            throws JwtSvidException {
        if (isClosed()) {
            throw new IllegalStateException("JWT SVID source is closed");
        }

        return getJwtSvids(subject, audience, extraAudiences);
    }

    /**
     * Returns the JWT bundle for a given trust domain.
     *
     * @return an instance of a {@link X509Bundle}
     * @throws BundleNotFoundException is there is no bundle for the trust domain provided
     * @throws IllegalStateException   if the source is closed
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

    // Check if the jwtSvids map contains the cacheKey, returns it if it does and the JWT SVID has not past its half lifetime.
    // If the cache does not contain the key or the JWT SVID has past its half lifetime, make a new FetchJWTSVID call to the Workload API,
    // adds the JWT SVIDs to the cache map and returns them.
    // Only one thread can fetch new JWT SVIDs and update the cache at a time.
    private List<JwtSvid> getJwtSvids(SpiffeId subject, String audience, String... extraAudiences) throws JwtSvidException {
        Set<String> audiencesSet = getAudienceSet(audience, extraAudiences);
        ImmutablePair<SpiffeId, Set<String>> cacheKey = new ImmutablePair<>(subject, audiencesSet);

        List<JwtSvid> svidList = jwtSvids.get(cacheKey);
        if (svidList != null && !isTokenPastHalfLifetime(svidList.get(0))) {
            return svidList;
        }

        // even using ConcurrentHashMap, there is a possibility of multiple threads trying to fetch new JWT SVIDs at the same time.
        synchronized (this) {
            // Check again if the jwtSvids map contains the cacheKey, returns the entry if it does exist and the JWT SVID has not past its half lifetime,
            // if it does not exist or the JWT-SVID has past half its lifetime calls the Workload API to fetch new JWT-SVIDs,
            // adds them to the cache map and returns the list of them.
            svidList = jwtSvids.get(cacheKey);
            if (svidList != null && !isTokenPastHalfLifetime(svidList.get(0))) {
                return svidList;
            }

            if (cacheKey.left == null) {
                svidList = workloadApiClient.fetchJwtSvids(audience, extraAudiences);
            } else {
                svidList = workloadApiClient.fetchJwtSvids(cacheKey.left, audience, extraAudiences);
            }
            jwtSvids.put(cacheKey, svidList);
            return svidList;
        }
    }

    private static Set<String> getAudienceSet(String audience, String[] extraAudiences) {
        Set<String> audiencesString;
        if (extraAudiences != null && extraAudiences.length > 0) {
            audiencesString = new HashSet<>(Arrays.asList(extraAudiences));
            audiencesString.add(audience);
        } else {
            audiencesString = Collections.singleton(audience);
        }
        return audiencesString;
    }

    private boolean isTokenPastHalfLifetime(JwtSvid jwtSvid) {
        Instant now = clock.instant();
        val halfLife = new Date(jwtSvid.getExpiry().getTime() - (jwtSvid.getExpiry().getTime() - jwtSvid.getIssuedAt().getTime()) / 2);
        val halfLifeInstant = Instant.ofEpochMilli(halfLife.getTime());
        return now.isAfter(halfLifeInstant);
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
                .spiffeSocketPath(options.getSpiffeSocketPath())
                .build();
        return DefaultWorkloadApiClient.newClient(clientOptions);
    }

    void setClock(Clock clock) {
        this.clock = clock;
    }
}
