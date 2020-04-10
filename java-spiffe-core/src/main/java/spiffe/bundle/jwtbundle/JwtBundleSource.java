package spiffe.bundle.jwtbundle;

import lombok.NonNull;
import spiffe.spiffeid.TrustDomain;

import java.util.Optional;

/**
 * A <code>JwtBundleSource</code> represents a source of JWT-Bundles.
 */
public interface JwtBundleSource {

    /**
     * Returns the JWT bundle for a trustDomain.
     *
     * @param trustDomain an instance of a TrustDomain
     * @return an Optional with an JwtBundle, Optional.empty if not found.
     */
    Optional<JwtBundle> getJwtBundleForTrustDomain(@NonNull final TrustDomain trustDomain);
}
