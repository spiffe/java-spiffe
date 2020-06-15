package spiffe.bundle;


import lombok.NonNull;
import spiffe.exception.BundleNotFoundException;
import spiffe.spiffeid.TrustDomain;

/**
 * A <code>BundleSource</code> represents a source of bundles of type T keyed by trust domain.
 */
public interface BundleSource<T> {

    /**
     * Returns the bundle of type T associated to the given trust domain.
     *
     * @param trustDomain an instance of a {@link TrustDomain}
     * @return the a bundle of type T for the given trust domain
     * @throws BundleNotFoundException if no bundle is found for the given trust domain
     */
    T getBundleForTrustDomain(@NonNull final TrustDomain trustDomain) throws BundleNotFoundException;
}
