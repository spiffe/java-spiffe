package spiffe.bundle.x509bundle;


import lombok.NonNull;
import spiffe.spiffeid.TrustDomain;

import java.util.Optional;

/**
 * A <code>X509BundleSource</code> represents a source of X509-Bundles keyed by TrustDomain.
 */
public interface X509BundleSource {

    /**
     * Returns the bundle associated to a trustDomain.
     *
     * @param trustDomain an instance of a TrustDomain
     * @return an Optional with an X509Bundle, Optional.empty if not found.
     */
    Optional<X509Bundle> getX509BundleForTrustDomain(@NonNull final TrustDomain trustDomain);

}
