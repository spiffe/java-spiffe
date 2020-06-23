package io.spiffe.svid.jwtsvid;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.spiffe.Algorithm;
import io.spiffe.bundle.BundleSource;
import io.spiffe.bundle.jwtbundle.JwtBundle;
import io.spiffe.exception.AuthorityNotFoundException;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.exception.JwtSvidException;
import io.spiffe.spiffeid.SpiffeId;
import lombok.NonNull;
import lombok.Value;
import lombok.val;
import org.apache.commons.lang3.StringUtils;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Represents a SPIFFE JWT-SVID.
 */
@Value
public class JwtSvid {

    /**
     * SPIFFE ID of the JWT-SVID as present in the 'sub' claim.
     */
    SpiffeId spiffeId;

    /**
     * Audience is the intended recipients of JWT-SVID as present in the 'aud' claim.
     */
    Set<String> audience;

    /**
     * Expiration time of JWT-SVID as present in 'exp' claim.
     */
    Date expiry;

    /**
     * Parsed claims from token.
     */
    Map<String, Object> claims;

    /**
     * Serialized JWT token.
     */
    String token;

    /**
     * Constructor
     *
     * @param spiffeId {@link SpiffeId} of the JWT-SVID
     * @param audience list of audiences
     * @param expiry the Date of expiration
     * @param claims map of claims
     * @param token the token as string
     */
    JwtSvid(@NonNull final SpiffeId spiffeId,
            @NonNull final Set<String> audience,
            @NonNull final Date expiry,
            @NonNull final Map<String, Object> claims,
            @NonNull final String token) {
        this.spiffeId = spiffeId;
        this.audience = audience;
        this.expiry = expiry;
        this.claims = claims;
        this.token = token;
    }

    /**
     * Parses and validates a JWT-SVID token and returns an instance of {@link JwtSvid}.
     * <p>
     * The JWT-SVID signature is verified using the JWT bundle source.
     *
     * @param token           a token as a string that is parsed and validated
     * @param jwtBundleSource an implementation of a {@link BundleSource} that provides the JWT authorities to verify the signature
     * @param audience        audience as a list of strings used to validate the 'aud' claim
     * @return an instance of a {@link JwtSvid} with a SPIFFE ID parsed from the 'sub', audience from 'aud', and expiry
     * from 'exp' claim.
     * @throws JwtSvidException when the token expired or the expiration claim is missing,
     *                                           when the algorithm is not supported, when the header 'kid' is missing, when the signature cannot be verified, or
     *                                           when the 'aud' claim has an audience that is not in the audience list provided as parameter
     * @throws IllegalArgumentException          when the token is blank or cannot be parsed
     * @throws BundleNotFoundException           if the bundle for the trust domain of the spiffe id from the 'sub' cannot be found
     *                                           in the JwtBundleSource
     * @throws AuthorityNotFoundException        if the authority cannot be found in the bundle using the value from the 'kid' header
     */
    public static JwtSvid parseAndValidate(@NonNull final String token,
                                           @NonNull final BundleSource<JwtBundle> jwtBundleSource,
                                           @NonNull final Set<String> audience)
            throws JwtSvidException, BundleNotFoundException, AuthorityNotFoundException {

        if (StringUtils.isBlank(token)) {
            throw new IllegalArgumentException("Token cannot be blank");
        }

        val signedJwt = getSignedJWT(token);
        val claimsSet = getJwtClaimsSet(signedJwt);

        val claimAudience = new HashSet<>(claimsSet.getAudience());
        validateAudience(claimAudience, audience);

        val expirationTime = claimsSet.getExpirationTime();
        validateExpiration(expirationTime);

        val spiffeId = getSpiffeIdOfSubject(claimsSet);
        val jwtBundle = jwtBundleSource.getBundleForTrustDomain(spiffeId.getTrustDomain());

        val keyId = getKeyId(signedJwt.getHeader());
        val jwtAuthority = jwtBundle.findJwtAuthority(keyId);

        val algorithm = signedJwt.getHeader().getAlgorithm().getName();
        verifySignature(signedJwt, jwtAuthority, algorithm, keyId);

        return new JwtSvid(spiffeId, claimAudience, expirationTime, claimsSet.getClaims(), token);
    }

    /**
     * Parses and validates a JWT-SVID token and returns an instance of a {@link JwtSvid}.
     * <p>
     * The JWT-SVID signature is not verified.
     *
     * @param token    a token as a string that is parsed and validated
     * @param audience audience as a list of strings used to validate the 'aud' claim
     * @return an instance of a {@link JwtSvid} with a SPIFFE ID parsed from the 'sub', audience from 'aud', and expiry
     * from 'exp' claim.
     * @throws JwtSvidException when the token expired or the expiration claim is missing, or when
     *                                           the 'aud' has an audience that is not in the audience provided as parameter
     * @throws IllegalArgumentException          when the token cannot be parsed
     */
    public static JwtSvid parseInsecure(@NonNull final String token, @NonNull final Set<String> audience) throws JwtSvidException {
        if (StringUtils.isBlank(token)) {
            throw new IllegalArgumentException("Token cannot be blank");
        }

        val signedJwt = getSignedJWT(token);
        val claimsSet = getJwtClaimsSet(signedJwt);

        val claimAudience = new HashSet<>(claimsSet.getAudience());
        validateAudience(claimAudience, audience);

        val expirationTime = claimsSet.getExpirationTime();
        validateExpiration(expirationTime);

        val spiffeId = getSpiffeIdOfSubject(claimsSet);

        return new JwtSvid(spiffeId, claimAudience, expirationTime, claimsSet.getClaims(), token);
    }

    /**
     * Returns the JWT-SVID marshaled to a string. The returned value is the same token value originally passed
     * to the parseAndValidate method.
     *
     * @return the token as String
     */
    public String marshal() {
        return token;
    }

    /**
     * @return a copy of the expiration date time of the JWT SVID.
     */
    public Date getExpiry() {
        // defensive copy to prevent exposing a mutable object
        return new Date(expiry.getTime());
    }

    /**
     * @return the map of claims
     */
    public Map<String, Object> getClaims() {
        return Collections.unmodifiableMap(claims);
    }

    /**
     * @return the Set of audiences
     */
    public Set<String> getAudience() {
        return Collections.unmodifiableSet(audience);
    }

    private static JWTClaimsSet getJwtClaimsSet(final SignedJWT signedJwt) {
        final JWTClaimsSet claimsSet;
        try {
            claimsSet = signedJwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new IllegalArgumentException("Unable to parse JWT token", e);
        }
        return claimsSet;
    }

    private static SignedJWT getSignedJWT(final String token) {
        final SignedJWT signedJwt;
        try {
            signedJwt = SignedJWT.parse(token);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Unable to parse JWT token", e);
        }
        return signedJwt;
    }

    private static void verifySignature(final SignedJWT signedJwt, final PublicKey jwtAuthority, final String algorithm, final String keyId) throws JwtSvidException {
        boolean verify;
        try {
            val verifier = getJwsVerifier(jwtAuthority, algorithm);
            verify = signedJwt.verify(verifier);
        } catch (ClassCastException | JOSEException e) {
            throw new JwtSvidException(String.format("Error verifying signature with the authority with keyId=%s", keyId), e);
        }

        if (!verify) {
            throw new JwtSvidException(String.format("Signature invalid: cannot be verified with the authority with keyId=%s", keyId));
        }
    }

    private static JWSVerifier getJwsVerifier(final PublicKey jwtAuthority, final String algorithm) throws JOSEException, JwtSvidException {
        JWSVerifier verifier;
        final Algorithm alg = Algorithm.parse(algorithm);
        if (Algorithm.Family.EC.contains(alg)) {
            verifier = new ECDSAVerifier((ECPublicKey) jwtAuthority);
        } else if (Algorithm.Family.RSA.contains(alg)) {
            verifier = new RSASSAVerifier((RSAPublicKey) jwtAuthority);
        } else {
            throw new JwtSvidException(String.format("Unsupported token signature algorithm %s", algorithm));
        }
        return verifier;
    }

    private static String getKeyId(final JWSHeader header) throws JwtSvidException {
        val keyId = header.getKeyID();
        if (keyId == null) {
            throw new JwtSvidException("Token header missing key id");
        }
        if (StringUtils.isBlank(keyId)) {
            throw new JwtSvidException("Token header key id contains an empty value");
        }
        return keyId;
    }

    private static void validateExpiration(final Date expirationTime) throws JwtSvidException {
        if (expirationTime == null) {
            throw new JwtSvidException("Token missing expiration claim");
        }

        if (expirationTime.before(new Date())) {
            throw new JwtSvidException("Token has expired");
        }
    }

    private static SpiffeId getSpiffeIdOfSubject(final JWTClaimsSet claimsSet) throws JwtSvidException {
        val subject = claimsSet.getSubject();
        if (StringUtils.isBlank(subject)) {
            throw new JwtSvidException("Token missing subject claim");
        }

        try {
            return SpiffeId.parse(subject);
        } catch (IllegalArgumentException e) {
            throw new JwtSvidException(String.format("Subject %s cannot be parsed as a SPIFFE ID", subject), e);
        }

    }

    private static void validateAudience(final Set<String> audClaim, final Set<String> expectedAudience) throws JwtSvidException {
        for (String aud : audClaim) {
            if (!expectedAudience.contains(aud)) {
                throw new JwtSvidException(String.format("expected audience in %s (audience=%s)", expectedAudience, audClaim));
            }
        }
    }
}
