package spiffe.bundle.jwtbundle;

import lombok.NonNull;
import spiffe.exception.BundleNotFoundException;
import spiffe.spiffeid.TrustDomain;

/**
 * A <code>JwtBundleSource</code> represents a source of JWT bundles.
 */
public interface JwtBundleSource {

    /**
     * Returns the JWT bundle for a trust domain.
     *
     * @param trustDomain an instance of a {@link TrustDomain}
     * @return the {@link JwtBundle} for the given trust domain
     *
     * @throws BundleNotFoundException if no bundle is found for the given trust domain.
     */
    JwtBundle getJwtBundleForTrustDomain(@NonNull final TrustDomain trustDomain) throws BundleNotFoundException;
}
