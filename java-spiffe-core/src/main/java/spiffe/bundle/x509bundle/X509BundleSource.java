package spiffe.bundle.x509bundle;


import lombok.NonNull;
import spiffe.result.Result;
import spiffe.spiffeid.TrustDomain;

/**
 * A <code>X509BundleSource</code> represents a source of X509-Bundles keyed by TrustDomain.
 */
public interface X509BundleSource {

    /**
     * Returns the bundle associated to a trustDomain.
     *
     * @param trustDomain an instance of a TrustDomain
     * @return a {@link spiffe.result.Ok} containing a {@link X509Bundle}, or a {@link spiffe.result.Error} if
     * no bundle is found for the given trust domain.
     */
    Result<X509Bundle, String> getX509BundleForTrustDomain(@NonNull final TrustDomain trustDomain);

}
