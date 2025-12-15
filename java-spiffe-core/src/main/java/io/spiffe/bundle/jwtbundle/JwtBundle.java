package io.spiffe.bundle.jwtbundle;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import io.spiffe.internal.JwtSignatureAlgorithm;
import io.spiffe.bundle.BundleSource;
import io.spiffe.exception.AuthorityNotFoundException;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.exception.JwtBundleException;
import io.spiffe.spiffeid.TrustDomain;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyException;
import java.security.PublicKey;
import java.text.ParseException;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Represents a collection of trusted JWT authorities (Public Keys) for a trust domain.
 */
public final class JwtBundle implements BundleSource<JwtBundle> {

    private final TrustDomain trustDomain;

    private final Map<String, PublicKey> jwtAuthorities;

    /**
     * Creates a new JWT bundle for a trust domain.
     *
     * @param trustDomain a {@link TrustDomain} to associate to the JwtBundle
     */
    public JwtBundle(TrustDomain trustDomain) {
        this.trustDomain = Objects.requireNonNull(trustDomain, "trustDomain must not be null");
        this.jwtAuthorities = new ConcurrentHashMap<>();
    }

    /**
     * Creates a new JWT bundle for a trust domain with JWT Authorities (public keys associated to keyIds).
     *
     * @param trustDomain    a {@link TrustDomain} to associate to the JwtBundle
     * @param jwtAuthorities a Map of public Keys
     */
    public JwtBundle(TrustDomain trustDomain,
                     Map<String, PublicKey> jwtAuthorities) {
        this.trustDomain = Objects.requireNonNull(trustDomain, "trustDomain must not be null");
        Objects.requireNonNull(jwtAuthorities, "jwtAuthorities must not be null");
        this.jwtAuthorities = new ConcurrentHashMap<>(jwtAuthorities);
    }

    /**
     * Loads a JWT bundle from a file on disk. The file must contain a standard RFC 7517 JWKS document.
     * <p>
     * Key Types supported are EC and RSA.
     *
     * @param trustDomain a {@link TrustDomain} to associate to the JWT bundle.
     * @param bundlePath  a path to a file containing the JWT authorities (public keys).
     * @return an instance of a {@link JwtBundle}
     * @throws JwtBundleException if there is an error reading or parsing the file, or if a keyId is empty
     * @throws KeyException       if the bundle file contains a key type that is not supported
     */
    public static JwtBundle load(TrustDomain trustDomain,
                                 Path bundlePath)
            throws KeyException, JwtBundleException {
        Objects.requireNonNull(trustDomain, "trustDomain must not be null");
        Objects.requireNonNull(bundlePath, "bundlePath must not be null");

        try {
            JWKSet jwkSet = JWKSet.load(bundlePath.toFile());
            return toJwtBundle(trustDomain, jwkSet);
        } catch (IllegalArgumentException | IOException | ParseException | JOSEException e) {
            String error = "Could not load bundle from file: %s";
            throw new JwtBundleException(String.format(error, bundlePath.toString()), e);
        }
    }

    /**
     * Parses a JWT bundle from a byte array.
     *
     * @param trustDomain a {@link TrustDomain}
     * @param bundleBytes an array of bytes representing the JWT bundle.
     * @return an instance of a {@link JwtBundle}
     * @throws JwtBundleException if there is an error reading or parsing the file, or if a keyId is empty
     */
    public static JwtBundle parse(
            TrustDomain trustDomain,
            byte[] bundleBytes)
            throws JwtBundleException {
        Objects.requireNonNull(trustDomain, "trustDomain must not be null");
        Objects.requireNonNull(bundleBytes, "bundleBytes must not be null");

        try {
            JWKSet jwkSet = JWKSet.parse(new String(bundleBytes));
            return toJwtBundle(trustDomain, jwkSet);
        } catch (ParseException | JOSEException | KeyException e) {
            throw new JwtBundleException("Could not parse bundle from bytes", e);
        }
    }

    /**
     * Returns the JWT bundle for a trust domain.
     *
     * @param trustDomain a {@link TrustDomain}
     * @return a {@link JwtBundle} for the trust domain
     * @throws BundleNotFoundException if there is no bundle for the given trust domain
     */
    @Override
    public JwtBundle getBundleForTrustDomain(TrustDomain trustDomain) throws BundleNotFoundException {
        Objects.requireNonNull(trustDomain, "trustDomain must not be null");
        if (this.trustDomain.equals(trustDomain)) {
            return this;
        }
        throw new BundleNotFoundException(
                String.format("No JWT bundle found for trust domain %s", trustDomain));
    }

    /**
     * Returns the JWT authorities in the bundle, keyed by key ID.
     *
     * @return the JWT authorities in the bundle, keyed by key ID
     */
    public Map<String, PublicKey> getJwtAuthorities() {
        return Collections.unmodifiableMap(jwtAuthorities);
    }

    /**
     * Finds the JWT key with the given key id from the bundle.
     *
     * @param keyId the Key ID
     * @return {@link PublicKey} representing the Authority associated to the KeyID.
     * @throws AuthorityNotFoundException if no Authority is found associated to the Key ID
     */
    public PublicKey findJwtAuthority(String keyId) throws AuthorityNotFoundException {
        Objects.requireNonNull(keyId, "keyId must not be null");
        PublicKey key = jwtAuthorities.get(keyId);
        if (key != null) {
            return key;
        }
        throw new AuthorityNotFoundException(
                String.format("No authority found for the trust domain %s and key id %s",
                        this.trustDomain, keyId));
    }

    /**
     * Looks for a JWT authority id in the JWT bundle.
     *
     * @param keyId id of a JWT Authority
     * @return true if the bundle has a JWT authority with the given key ID.
     */
    public boolean hasJwtAuthority(String keyId) {
        Objects.requireNonNull(keyId, "keyId must not be null");
        return jwtAuthorities.containsKey(keyId);
    }

    /**
     * Adds a JWT authority to the bundle. If a JWT authority already exists
     * under the given key ID, it is replaced. A key ID must be specified.
     *
     * @param keyId        Key ID to associate to the jwtAuthority
     * @param jwtAuthority a PublicKey
     */
    public void putJwtAuthority(String keyId, PublicKey jwtAuthority) {
        Objects.requireNonNull(keyId, "keyId must not be null");
        Objects.requireNonNull(jwtAuthority, "jwtAuthority must not be null");
        if (StringUtils.isBlank(keyId)) {
            throw new IllegalArgumentException("KeyId cannot be empty");
        }
        jwtAuthorities.put(keyId, jwtAuthority);
    }

    /**
     * Removes the JWT authority identified by the key ID from the bundle.
     *
     * @param keyId The key id of the JWT authority to be removed
     */
    public void removeJwtAuthority(String keyId) {
        Objects.requireNonNull(keyId, "keyId must not be null");
        jwtAuthorities.remove(keyId);
    }

    private static JwtBundle toJwtBundle(TrustDomain trustDomain,
                                         JWKSet jwkSet)
            throws JwtBundleException, JOSEException, ParseException, KeyException {

        Objects.requireNonNull(trustDomain, "trustDomain must not be null");
        Objects.requireNonNull(jwkSet, "jwkSet must not be null");

        final Map<String, PublicKey> authorities = new ConcurrentHashMap<>();
        for (JWK jwk : jwkSet.getKeys()) {
            String keyId = getKeyId(jwk);
            PublicKey publicKey = getPublicKey(jwk);
            authorities.put(keyId, publicKey);
        }
        return new JwtBundle(trustDomain, authorities);
    }

    private static String getKeyId(final JWK jwk) throws JwtBundleException {
        Objects.requireNonNull(jwk, "jwk must not be null");
        String keyId = jwk.getKeyID();
        if (StringUtils.isBlank(keyId)) {
            throw new JwtBundleException("Error adding authority of JWKS: keyID cannot be empty");
        }
        return keyId;
    }

    private static PublicKey getPublicKey(final JWK jwk)
            throws JOSEException, ParseException, KeyException {
        Objects.requireNonNull(jwk, "jwk must not be null");

        JwtSignatureAlgorithm.Family family =
                JwtSignatureAlgorithm.Family.parse(jwk.getKeyType().getValue());

        final PublicKey publicKey;
        switch (family) {
            case EC:
                publicKey = ECKey.parse(jwk.toJSONString()).toPublicKey();
                break;
            case RSA:
                publicKey = RSAKey.parse(jwk.toJSONString()).toPublicKey();
                break;
            default:
                throw new KeyException(
                        String.format("Key Type not supported: %s", jwk.getKeyType().getValue()));
        }
        return publicKey;
    }

    public TrustDomain getTrustDomain() {
        return trustDomain;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof JwtBundle)) return false;
        JwtBundle jwtBundle = (JwtBundle) o;
        return Objects.equals(trustDomain, jwtBundle.trustDomain) &&
                Objects.equals(jwtAuthorities, jwtBundle.jwtAuthorities);
    }

    @Override
    public int hashCode() {
        return Objects.hash(trustDomain, jwtAuthorities);
    }

    @Override
    public String toString() {
        return "JwtBundle(" +
                "trustDomain=" + trustDomain +
                ", jwtAuthorities=" + jwtAuthorities +
                ')';
    }
}
