package io.spiffe.bundle;


import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.spiffeid.TrustDomain;

/**
 * Represents a source of bundles of type T keyed by trust domain.
 */
public interface BundleSource<T> {

    /**
     * Returns the bundle of type T associated to the given trust domain.
     *
     * @param trustDomain an instance of a {@link TrustDomain}
     * @return the a bundle of type T for the given trust domain
     * @throws BundleNotFoundException if no bundle is found for the given trust domain
     */
    T getBundleForTrustDomain(TrustDomain trustDomain) throws BundleNotFoundException;
}
