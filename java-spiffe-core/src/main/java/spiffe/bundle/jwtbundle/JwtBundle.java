package spiffe.bundle.jwtbundle;

import lombok.NonNull;
import lombok.Value;
import org.apache.commons.lang3.NotImplementedException;
import org.apache.commons.lang3.StringUtils;
import spiffe.exception.AuthorityNotFoundException;
import spiffe.exception.BundleNotFoundException;
import spiffe.spiffeid.TrustDomain;

import java.nio.file.Path;
import java.security.PublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A <code>JwtBundle</code> represents a collection of trusted JWT authorities for a trust domain.
 */
@Value
public class JwtBundle implements JwtBundleSource {

    TrustDomain trustDomain;

    Map<String, PublicKey> jwtAuthorities;

    public JwtBundle(@NonNull TrustDomain trustDomain, @NonNull Map<String, PublicKey> jwtAuthorities) {
        this.trustDomain = trustDomain;
        this.jwtAuthorities = new ConcurrentHashMap<>(jwtAuthorities);
    }

    public JwtBundle(@NonNull TrustDomain trustDomain) {
        this.trustDomain = trustDomain;
        this.jwtAuthorities = new ConcurrentHashMap<>();
    }

    /**
     * Creates a new bundle from JWT public keys.
     *
     * @param trustDomain a {@link TrustDomain} to associate to the JwtBundle
     * @param jwtAuthorities     a Map of public Keys
     * @return a new {@link JwtBundle}.
     */
    public static JwtBundle fromJWTAuthorities(@NonNull TrustDomain trustDomain, Map<String, PublicKey> jwtAuthorities) {
        throw new NotImplementedException("Not implemented");
    }

    /**
     * Loads a bundle from a file on disk.
     *
     * @param trustDomain a {@link TrustDomain} to associate to the JWT bundle.
     * @param bundlePath  a path to a file containing the JWT bundle.
     * @return a instance of a {@link JwtBundle}
     */
    public static JwtBundle load(
            @NonNull final TrustDomain trustDomain,
            @NonNull final Path bundlePath) {
        throw new NotImplementedException("Not implemented");
    }

    /**
     * Parses a bundle from a byte array.
     *
     * @param trustDomain a {@link TrustDomain}
     * @param bundleBytes an array of bytes representing the JWT bundle.
     * @return an instance of a {@link JwtBundle}
     */
    public static JwtBundle parse(
            @NonNull final TrustDomain trustDomain,
            @NonNull final byte[] bundleBytes) {
        throw new NotImplementedException("Not implemented");
    }

    /**
     * Returns the JWT bundle for a trust domain.
     *
     * @param trustDomain a {@link TrustDomain}
     * @return a {@link JwtBundle} for the trust domain
     *
     * @throws BundleNotFoundException if there is no bundle for the given trust domain
     */
    @Override
    public JwtBundle getJwtBundleForTrustDomain(TrustDomain trustDomain) throws BundleNotFoundException {
        if (this.trustDomain.equals(trustDomain)) {
            return this;
        }
        throw new BundleNotFoundException(String.format("No JWT bundle found for trust domain %s", trustDomain));
    }

    /**
     * Finds the JWT key with the given key id from the bundle.
     *
     * @param keyId the Key ID
     * @return {@link PublicKey} representing the Authority associated to the KeyID.
     *
     * @throws AuthorityNotFoundException if no Authority is found associated to the Key ID
     */
    public PublicKey findJwtAuthority(String keyId) throws AuthorityNotFoundException {
        PublicKey key = jwtAuthorities.get(keyId);
        if (key != null) {
            return key;
        }
        throw new AuthorityNotFoundException(String.format("No authority found for the trust domain %s and key id %s", this.trustDomain, keyId));
    }

    public void addJWTAuthority(String keyId, PublicKey jwtAuthority) {
        if (StringUtils.isBlank(keyId)) {
            throw new IllegalArgumentException("KeyId cannot be empty");
        }

        jwtAuthorities.put(keyId, jwtAuthority);
    }
}
