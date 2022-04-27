package io.spiffe.svid.jwtsvid;

import io.spiffe.exception.JwtSvidException;
import io.spiffe.spiffeid.SpiffeId;
import lombok.NonNull;

import java.util.List;

/**
 * Represents a source of SPIFFE JWT-SVIDs.
 */
public interface JwtSvidSource {

    /**
     * Fetches a JWT-SVID from the source with the given audiences.
     *
     * @param audience       the audience
     * @param extraAudiences a list of extra audiences as an array of String
     * @return a {@link JwtSvid}
     * @throws JwtSvidException when there is an error fetching the JWT SVID
     */
    JwtSvid fetchJwtSvid(String audience, String... extraAudiences) throws JwtSvidException;

    /**
     * Fetches a JWT-SVID from the source with the given subject and audiences.
     *
     * @param subject        a {@link SpiffeId}
     * @param audience       the audience
     * @param extraAudiences a list of extra audiences as an array of String
     * @return a {@link JwtSvid}
     * @throws JwtSvidException when there is an error fetching the JWT SVID
     */
    JwtSvid fetchJwtSvid(SpiffeId subject, String audience, String... extraAudiences) throws JwtSvidException;

    /**
     * Fetches all SPIFFE JWT-SVIDs on one-shot blocking call.
     *
     * @param audience      the audience of the JWT-SVID
     * @param extraAudience the extra audience for the JWT_SVID
     * @return all of {@link JwtSvid} object
     * @throws JwtSvidException if there is an error fetching or processing the JWT from the Workload API
     */
    List<JwtSvid> fetchJwtSvids(@NonNull String audience, String... extraAudience) throws JwtSvidException;

    /**
     * Fetches all SPIFFE JWT-SVIDs on one-shot blocking call.
     *
     * @param subject       a SPIFFE ID
     * @param audience      the audience of the JWT-SVID
     * @param extraAudience the extra audience for the JWT_SVID
     * @return all of {@link JwtSvid} object
     * @throws JwtSvidException if there is an error fetching or processing the JWT from the Workload API
     */
    List<JwtSvid> fetchJwtSvids(@NonNull SpiffeId subject, @NonNull String audience, String... extraAudience) throws JwtSvidException;
}
