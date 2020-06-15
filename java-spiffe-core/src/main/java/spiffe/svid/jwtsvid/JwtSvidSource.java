package spiffe.svid.jwtsvid;

import spiffe.exception.JwtSvidException;
import spiffe.spiffeid.SpiffeId;

/**
 * Represents a source of SPIFFE JWT-SVIDs.
 */
public interface JwtSvidSource {

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
}
