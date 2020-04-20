package spiffe.bundle.jwtbundle;

import lombok.NonNull;
import spiffe.result.Result;
import spiffe.spiffeid.TrustDomain;

/**
 * A <code>JwtBundleSource</code> represents a source of JWT-Bundles.
 */
public interface JwtBundleSource {

    /**
     * Returns the JWT bundle for a trustDomain.
     *
     * @param trustDomain an instance of a TrustDomain
     * @return a {@link spiffe.result.Ok} containing a {@link JwtBundle}, or a {@link spiffe.result.Error} if
     * no bundle is found for the given trust domain.
     */
    Result<JwtBundle, String> getJwtBundleForTrustDomain(@NonNull final TrustDomain trustDomain);
}
