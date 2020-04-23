package spiffe.bundle.jwtbundle;

import lombok.NonNull;
import lombok.Value;
import org.apache.commons.lang3.NotImplementedException;
import spiffe.result.Result;
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
     * @param trustDomain a TrustDomain to associate to the JwtBundle
     * @param jwtKeys     a Map of Public Keys
     * @return a new JwtBundle.
     */
    public static JwtBundle fromJWTKeys(@NonNull TrustDomain trustDomain, Map<String, PublicKey> jwtKeys) {
        throw new NotImplementedException("Not implemented");
    }

    /**
     * Loads a bundle from a file on disk.
     *
     * @param trustDomain a TrustDomain to associate to the JwtBundle.
     * @param bundlePath  a path to a file containing the JwtBundle.
     * @return a <code>Result.ok(jwtBundle)</code>, or a <code>Result.error(errorMessage)</code>
     */
    public static Result<JwtBundle, String > load(
            @NonNull final TrustDomain trustDomain,
            @NonNull final Path bundlePath) {
        throw new NotImplementedException("Not implemented");
    }

    /**
     * Parses a bundle from a byte array.
     *
     * @param trustDomain a TrustDomain
     * @param bundleBytes an array of bytes representing the bundle.
     * @return
     */
    public static Result<JwtBundle, String> parse(
            @NonNull final TrustDomain trustDomain,
            @NonNull final byte[] bundleBytes) {
        throw new NotImplementedException("Not implemented");
    }

    /**
     * Returns the JwtBundle for a TrustDomain.
     *
     * @param trustDomain an instance of a TrustDomain
     * @return a {@link spiffe.result.Ok} containing the JwtBundle for the TrustDomain, or
     * an {@link spiffe.result.Error} if there is no bundle for the TrustDomain
     */
    @Override
    public Result<JwtBundle, String> getJwtBundleForTrustDomain(TrustDomain trustDomain) {
        if (this.trustDomain.equals(trustDomain)) {
            return Result.ok(this);
        }
        return Result.error("No JWT bundle for trust domain %s", trustDomain);
    }

    /**
     * Finds the JWT key with the given key id from the bundle. If the key
     * is found, it returns an Optional wrapping the key. Otherwise,
     * it returns an Optional.empty().
     *
     * @param keyId the Key ID
     * @return an {@link Optional} containing a PublicKey.
     */
    public Optional<PublicKey> findJwtKey(String keyId) {
        throw new NotImplementedException("Not implemented");
    }

    /**
     * Returns the trust domain that the bundle belongs to.
     */
    public TrustDomain getTrustDomain() {
        return trustDomain;
    }
}
