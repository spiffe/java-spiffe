package spiffe.svid.jwtsvid;

import spiffe.spiffeid.SpiffeId;

/**
 * A <code>JwtSvidSource</code> represents a source of SPIFFE JWT-SVIDs.
 */
public interface JwtSvidSource {

    /**
     * Fetches a JWT-SVID from the source with the given parameters
     *
     * @param subject a {@link SpiffeId}
     * @param audience the audience
     * @param extraAudiences an array of Strings
     * @return a {@link JwtSvid}
     *
     * @throws //TODO: declare thrown exceptions
     */
    JwtSvid FetchJwtSvid(SpiffeId subject, String audience, String... extraAudiences);
}
