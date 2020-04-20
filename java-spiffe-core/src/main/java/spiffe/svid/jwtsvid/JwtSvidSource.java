package spiffe.svid.jwtsvid;

import spiffe.result.Result;
import spiffe.spiffeid.SpiffeId;

/**
 * A <code>JwtSvidSource</code> represents a source of SPIFFE JWT-SVIDs.
 */
public interface JwtSvidSource {

    /**
     * Fetches a JWT-SVID from the source with the given parameters
     *
     * @param subject a SpiffeId
     * @param audience the audience
     * @param extraAudiences an array of Strings
     * @return a JwtSvid
     */
    Result<JwtSvid, String> FetchJwtSvid(SpiffeId subject, String audience, String... extraAudiences);
}
