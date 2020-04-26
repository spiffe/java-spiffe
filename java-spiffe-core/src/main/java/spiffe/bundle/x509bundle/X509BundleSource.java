package spiffe.bundle.x509bundle;


import lombok.NonNull;
import spiffe.exception.BundleNotFoundException;
import spiffe.spiffeid.TrustDomain;

/**
 * A <code>X509BundleSource</code> represents a source of X509 bundles keyed by trust domain.
 */
public interface X509BundleSource {

    /**
     * Returns the X509 bundle associated to the given trust domain.
     *
     * @param trustDomain an instance of a {@link TrustDomain}
     * @return the {@link X509Bundle} for the given trust domain
     * @throws BundleNotFoundException if no bundle is found for the given trust domain
     */
    X509Bundle getX509BundleForTrustDomain(@NonNull final TrustDomain trustDomain) throws BundleNotFoundException;
}
