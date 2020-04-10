package spiffe.svid.jwtsvid;

import lombok.NonNull;
import lombok.Value;
import org.apache.commons.lang3.NotImplementedException;
import spiffe.bundle.jwtbundle.JwtBundleSource;
import spiffe.result.Result;
import spiffe.spiffeid.SpiffeId;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * A <code>JwtSvid</code> represents a SPIFFE JWT-SVID.
 */
@Value
public class JwtSvid {

    /**
     * SPIFFE ID of the JWT-SVID as present in the 'sub' claim
     */
    SpiffeId spiffeId;

    /**
     * Audience is the intended recipients of JWT-SVID as present in the 'aud' claim
     */
    List<String> audience;

    /**
     * Expiration time of JWT-SVID as present in 'exp' claim
     */
    LocalDateTime expiry;

    /**
     * Parsed claims from token
     */
    Map<String, Object> claims;

    /**
     * Serialized JWT token
     */
    String token;


    /**
     * Parses and validates a JWT-SVID token and returns the
     * JWT-SVID. The JWT-SVID signature is verified using the JWT bundle source.
     *
     * @param token a token as a String
     * @param jwtBundleSource an implementation of a JwtBundleSource
     * @param audience the audience as a String
     * @return a JwtSvid or Error
     */
    public Result<JwtSvid, String> parseAndValidate(@NonNull final String token, @NonNull final JwtBundleSource jwtBundleSource, String... audience) {
        throw new NotImplementedException("Not implemented");
    }

    /**
     * Returns the JWT-SVID marshaled to a string. The returned value is
     * the same token value originally passed to ParseAndValidate.
     *
     * @return
     */
    public String marshall() {
        return token;
    }
}
