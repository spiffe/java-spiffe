package io.spiffe.workloadapi;

import io.spiffe.bundle.jwtbundle.JwtBundleSet;
import io.spiffe.bundle.x509bundle.X509BundleSet;
import io.spiffe.exception.JwtBundleException;
import io.spiffe.exception.JwtSvidException;
import io.spiffe.exception.X509BundleException;
import io.spiffe.exception.X509ContextException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.svid.jwtsvid.JwtSvid;

import java.io.Closeable;
import java.util.List;

/**
 * Represents a client to interact with the Workload API.
 * <p>
 * Supports one-shot calls and watch updates for X.509 and JWT SVIDs and bundles.
 */
public interface WorkloadApiClient extends Closeable {

    /**
     * Fetches an X.509 context on a one-shot blocking call.
     *
     * @return an instance of a {@link X509Context} containing the X.509 materials fetched from the Workload API
     * @throws X509ContextException if there is an error fetching or processing the X.509 context
     */
    X509Context fetchX509Context() throws X509ContextException;

    /**
     * Watches for X.509 context updates.
     * <p>
     * A new Stream to the Workload API is opened for each call to this method, so that the client starts getting
     * updates immediately after the Stream is ready and doesn't have to wait until the Workload API dispatches
     * the next update based on the SVIDs TTL.
     *
     * @param watcher an instance that implements a {@link Watcher}.
     */
    void watchX509Context(Watcher<X509Context> watcher);

    /**
     * Fetches the X.509 bundles on a one-shot blocking call.
     *
     * @return an instance of a {@link X509BundleSet} containing the X.509 bundles keyed by TrustDomain
     * @throws X509BundleException if there is an error fetching or processing the X.509 bundles
     */
    X509BundleSet fetchX509Bundles() throws X509BundleException;

    /**
     * Watches for X.509 bundles updates.
     * <p>
     * A new Stream to the Workload API is opened for each call to this method, so that the client starts getting
     * updates immediately after the Stream is ready and doesn't have to wait until the Workload API dispatches
     * the next update.
     *
     * @param watcher an instance that implements a {@link Watcher} for {@link X509BundleSet}.
     */
    void watchX509Bundles(Watcher<X509BundleSet> watcher);

    /**
     * Fetches a SPIFFE JWT-SVID on one-shot blocking call.
     *
     * @param audience      the audience of the JWT-SVID
     * @param extraAudience the extra audience for the JWT_SVID
     * @return an instance of a {@link JwtSvid}
     * @throws JwtSvidException if there is an error fetching or processing the JWT from the Workload API
     */
    JwtSvid fetchJwtSvid(String audience, String... extraAudience) throws JwtSvidException;

    /**
     * Fetches a SPIFFE JWT-SVID on one-shot blocking call.
     *
     * @param subject       a SPIFFE ID
     * @param audience      the audience of the JWT-SVID
     * @param extraAudience the extra audience for the JWT_SVID
     * @return an instance of a {@link JwtSvid}
     * @throws JwtSvidException if there is an error fetching or processing the JWT from the Workload API
     */
    JwtSvid fetchJwtSvid(SpiffeId subject, String audience, String... extraAudience) throws JwtSvidException;

    /**
     * Fetches all SPIFFE JWT-SVIDs on one-shot blocking call.
     *
     * @param audience      the audience of the JWT-SVID
     * @param extraAudience the extra audience for the JWT_SVID
     * @return all of {@link JwtSvid} object
     * @throws JwtSvidException if there is an error fetching or processing the JWT from the Workload API
     */
    List<JwtSvid> fetchJwtSvids(String audience, String... extraAudience) throws JwtSvidException;

    /**
     * Fetches a SPIFFE JWT-SVID on one-shot blocking call.
     *
     * @param subject       a SPIFFE ID
     * @param audience      the audience of the JWT-SVID
     * @param extraAudience the extra audience for the JWT_SVID
     * @return all of {@link JwtSvid} objectÏ
     * @throws JwtSvidException if there is an error fetching or processing the JWT from the Workload API
     */
    List<JwtSvid> fetchJwtSvids(SpiffeId subject, String audience, String... extraAudience) throws JwtSvidException;

    /**
     * Fetches the JWT bundles for JWT-SVID validation, keyed by trust domain.
     *
     * @return an instance of a {@link JwtBundleSet}
     * @throws JwtBundleException when there is an error getting or processing the response from the Workload API
     */
    JwtBundleSet fetchJwtBundles() throws JwtBundleException;

    /**
     * Validates the JWT-SVID token. The parsed and validated JWT-SVID is returned.
     *
     * @param token    JWT token
     * @param audience audience of the JWT
     * @return a {@link JwtSvid} if the token and audience could be validated.
     * @throws JwtSvidException when the token cannot be validated with the audience
     */
    JwtSvid validateJwtSvid(String token, String audience) throws JwtSvidException;

    /**
     * Watches for JWT bundles updates.
     * <p>
     * A new Stream to the Workload API is opened for each call to this method, so that the client starts getting
     * updates immediately after the Stream is ready and doesn't have to wait until the Workload API dispatches
     * the next update based on the SVIDs TTL.
     *
     * @param watcher receives the update for JwtBundles.
     */
    void watchJwtBundles(Watcher<JwtBundleSet> watcher);
}
