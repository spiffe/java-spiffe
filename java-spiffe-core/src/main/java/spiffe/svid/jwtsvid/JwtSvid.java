package spiffe.svid.jwtsvid;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import lombok.NonNull;
import lombok.Value;
import org.apache.commons.lang3.StringUtils;
import spiffe.bundle.jwtbundle.JwtBundle;
import spiffe.bundle.jwtbundle.JwtBundleSource;
import spiffe.exception.AuthorityNotFoundException;
import spiffe.exception.BundleNotFoundException;
import spiffe.exception.JwtSvidException;
import spiffe.spiffeid.SpiffeId;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * A <code>JwtSvid</code> represents a SPIFFE JWT-SVID.
 */
@Value
public class JwtSvid {

    private static final List<String> SUPPORTED_ALGORITHMS =
            Arrays.asList("RS256", "RS384", "RS512",
                    "ES256", "ES384", "ES384",
                    "PS256", "PS384", "PS512");

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
    Date expiry;

    /**
     * Parsed claims from token
     */
    Map<String, Object> claims;

    /**
     * Serialized JWT token
     */
    String token;

    JwtSvid(SpiffeId spiffeId, List<String> audience, Date expiry, Map<String, Object> claims, String token) {
        this.spiffeId = spiffeId;
        this.audience = audience;
        this.expiry = expiry;
        this.claims = claims;
        this.token = token;
    }

    /**
     * Parses and validates a JWT-SVID token and returns the
     * JWT-SVID. The JWT-SVID signature is verified using the JWT bundle source.
     *
     * @param token           a token as a string that is parsed and validated
     * @param jwtBundleSource an implementation of a {@link JwtBundleSource} that provides the authority to verify the signature
     * @param audience        audience as a List of String used to validate the 'aud' claim
     *
     * @return an instance of a {@link JwtSvid} with a spiffe id parsed from the 'sub', audience from 'aud', and expiry
     * from 'exp' claim.
     *
     * @throws spiffe.exception.JwtSvidException when the token expired or the expiration claim is missing,
     * when the algorithm is not supported, when the header 'kid' is missing, when the signature cannot be verified, or
     * when the 'aud' claim has an audience that is not in the audience list provided as parameter
     *
     * @throws IllegalArgumentException when the token cannot be parsed
     *
     * @throws BundleNotFoundException if the bundle for the trust domain of the spiffe id from the 'sub' cannot be found
     * in the JwtBundleSource
     * @throws AuthorityNotFoundException if the authority cannot be found in the bundle using the value from the 'kid' header
     */
    public static JwtSvid parseAndValidate(@NonNull final String token,
                                           @NonNull final JwtBundleSource jwtBundleSource,
                                           @NonNull List<String> audience)
            throws JwtSvidException, BundleNotFoundException, AuthorityNotFoundException {

        // first the token is decoded without signature verification
        // in order to get the KeyID and the trust domain that are needed
        // to find the Authority in the jwtBundleSource. Once the Authority
        // is found, the token signature is verified

        Jwt<?, ?> jwt = decodeToken(token);
        Claims claims = (Claims) jwt.getBody();
        List<String> aud = claims.get("aud", List.class);

        validateAlgorithm(jwt);
        validateAudience(aud, audience);
        if (claims.getExpiration() == null) {
            throw new JwtSvidException("Token missing expiration claim");
        }

        String keyId = (String) jwt.getHeader().get("kid");
        if (StringUtils.isBlank(keyId)) {
            throw new JwtSvidException("Token header missing key id");
        }

        SpiffeId spiffeId = getSubjectSpiffeId(claims);
        JwtBundle jwtBundle = jwtBundleSource.getJwtBundleForTrustDomain(spiffeId.getTrustDomain());
        PublicKey jwtAuthority = jwtBundle.findJwtAuthority(keyId);

        verifySignature(token, keyId, jwtAuthority);

        return new JwtSvid(spiffeId, aud, claims.getExpiration(), claims, token);
    }

    /**
     * Parses and validates a JWT-SVID token and returns the JWT-SVID. The JWT-SVID signature is not verified.
     *
     * @param token           a token as a string that is parsed and validated
     * @param audience        audience as a List of String used to validate the 'aud' claim
     *
     * @return an instance of a {@link JwtSvid} with a spiffe id parsed from the 'sub', audience from 'aud', and expiry
     * from 'exp' claim.
     *
     * @throws spiffe.exception.JwtSvidException when the token expired or the expiration claim is missing, or when
     * the 'aud' has an audience that is not in the audience provided as parameter
     * @throws IllegalArgumentException when the token cannot be parsed
     */
    public static JwtSvid parseInsecure(@NonNull final String token, List<String> audience) throws JwtSvidException {
        Jwt<?, ?> jwt = decodeToken(token);
        Claims claims = (Claims) jwt.getBody();
        List<String> aud = claims.get("aud", List.class);

        validateAlgorithm(jwt);
        validateAudience(aud, audience);
        if (claims.getExpiration() == null) {
            throw new JwtSvidException("Token missing expiration claim");
        }

        SpiffeId spiffeId = getSubjectSpiffeId(claims);
        return new JwtSvid(spiffeId, aud, claims.getExpiration(), claims, token);
    }

    /**
     * Returns the JWT-SVID marshaled to a string. The returned value is
     * the same token value originally passed to parseAndValidate.
     *
     * @return the token
     */
    public String marshall() {
        return token;
    }

    public Date getExpiry() {
        // defensive copying to prevent exposing a mutable object
        return new Date(expiry.getTime());
    }

    private static void verifySignature(@NonNull String token, String keyId, PublicKey jwtAuthority) throws JwtSvidException {
        JwtParser jwtParser = Jwts.parserBuilder().setSigningKey(jwtAuthority).build();
        try {
            // parse token with signature verification using the jwt authority (public key)
            jwtParser.parse(token);
        } catch (SignatureException e) {
            throw new JwtSvidException(String.format("Signature invalid: cannot be verified with the authority with keyId=%s", keyId), e);
        } catch (UnsupportedJwtException e) {
            throw new JwtSvidException(String.format("Authority mismatch: signature cannot be verified with the authority with keyId=%s", keyId), e);
        }
    }

    private static SpiffeId getSubjectSpiffeId(Claims claims) throws JwtSvidException {
        String subject = claims.getSubject();
        if (StringUtils.isBlank(subject)) {
            throw new JwtSvidException("Token missing subject claim");
        }

        try {
            return SpiffeId.parse(subject);
        } catch (Exception e) {
            throw new JwtSvidException(String.format("Subject %s cannot be parsed as a SPIFFE ID", subject), e);
        }
    }

    private static void validateAudience(List<String> audClaim, List<String> audience) throws JwtSvidException {
        for (String aud : audClaim) {
            if (!audience.contains(aud)) {
                throw new JwtSvidException(String.format("expected audience in %s (audience=%s)", audience, audClaim));
            }
        }
    }

    private static void validateAlgorithm(Jwt<?, ?> jwt) throws JwtSvidException {
        String algorithm = (String) jwt.getHeader().get("alg");
        if (!SUPPORTED_ALGORITHMS.contains(algorithm)) {
            throw new JwtSvidException(String.format("Unsupported token signature algorithm %s", algorithm));
        }
    }

    private static Jwt<?, ?> decodeToken(String token) throws JwtSvidException {
        String[] splitToken;
        try {
            splitToken = token.split("\\.");
            String unsignedToken = splitToken[0] + "." + splitToken[1] + ".";
            JwtParser jwtParser = Jwts.parserBuilder().build();
            return jwtParser.parse(unsignedToken);
        } catch (ExpiredJwtException e) {
            throw new JwtSvidException("Token has expired");
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to parse JWT token", e);
        }
    }
}
