package spiffe.bundle.jwtbundle;

import lombok.NonNull;
import lombok.Value;
import org.apache.commons.lang3.NotImplementedException;
import spiffe.exception.BundleNotFoundException;
import spiffe.spiffeid.TrustDomain;

import java.nio.file.Path;
import java.security.PublicKey;
import java.util.Map;
import java.util.Optional;

/**
 * A <code>JwtBundle</code> represents a collection of trusted JWT authorities for a trust domain.
 */
@Value
public class JwtBundle implements JwtBundleSource {

    TrustDomain trustDomain;

    Map<String, PublicKey> jwtAuthorities;

    private JwtBundle(TrustDomain trustDomain, Map<String, PublicKey> jwtAuthorities) {
        this.trustDomain = trustDomain;
        this.jwtAuthorities = jwtAuthorities;
    }

    /**
     * Creates a new bundle from JWT public keys.
     *
     * @param trustDomain a {@link TrustDomain} to associate to the JwtBundle
     * @param jwtKeys     a Map of public Keys
     * @return a new {@link JwtBundle}.
     */
    public static JwtBundle fromJWTKeys(@NonNull TrustDomain trustDomain, Map<String, PublicKey> jwtKeys) {
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
     * Finds the JWT key with the given key id from the bundle. If the key
     * is found, it returns an Optional wrapping the key. Otherwise,
     * it returns an Optional.empty().
     *
     * @param keyId the Key ID
     * @return an {@link Optional} containing a {@link PublicKey}.
     */
    public Optional<PublicKey> findJwtKey(String keyId)  {
        throw new NotImplementedException("Not implemented");
    }

    /**
     * Returns the trust domain that the bundle belongs to.
     */
    public TrustDomain getTrustDomain() {
        return trustDomain;
    }
}
