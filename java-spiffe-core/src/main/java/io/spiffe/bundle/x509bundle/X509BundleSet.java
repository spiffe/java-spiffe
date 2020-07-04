package io.spiffe.bundle.x509bundle;

import io.spiffe.bundle.BundleSource;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.spiffeid.TrustDomain;
import lombok.NonNull;
import lombok.Value;
import lombok.val;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Represents a set of X.509 bundles keyed by trust domain.
 */
@Value
public class X509BundleSet implements BundleSource<X509Bundle> {

    Map<TrustDomain, X509Bundle> bundles;

    private X509BundleSet(final Map<TrustDomain, X509Bundle> bundles) {
        this.bundles = new ConcurrentHashMap<>(bundles);
    }

    /**
     * Creates a new X.509 bundle set from a list of X.509 bundles.
     *
     * @param bundles Collection of {@link X509Bundle}
     * @return a {@link X509BundleSet} initialized with the list of bundles
     */
    public static X509BundleSet of(@NonNull final Collection<X509Bundle> bundles) {
        final Map<TrustDomain, X509Bundle> bundleMap = new ConcurrentHashMap<>();
        for (X509Bundle bundle : bundles) {
            bundleMap.put(bundle.getTrustDomain(), bundle);
        }
        return new X509BundleSet(bundleMap);
    }

    /**
     * Adds an X.509 bundle to this Set, if the trust domain already exists,
     * replaces the bundle.
     *
     * @param x509Bundle a {@link X509Bundle}
     */
    public void put(@NonNull final X509Bundle x509Bundle){
        bundles.put(x509Bundle.getTrustDomain(), x509Bundle);
    }

    /**
     * Returns the X.509 bundle associated to the trust domain.
     *
     * @param trustDomain an instance of a {@link TrustDomain}
     * @return the {@link X509Bundle} associated to the given trust domain
     * @throws BundleNotFoundException if no bundle could be found for the given trust domain
     */
    @Override
    public X509Bundle getBundleForTrustDomain(@NonNull final TrustDomain trustDomain) throws BundleNotFoundException {
        val bundle = bundles.get(trustDomain);
        if (bundle == null) {
            throw new BundleNotFoundException(String.format("No X.509 bundle for trust domain %s", trustDomain));
        }
        return bundle;
    }

    /**
     * Returns the X.509 bundles of this X.509 Bundle Set.
     *
     * @return the X.509 bundles of this X.509 Bundle Set
     */
    public Map<TrustDomain, X509Bundle> getBundles() {
        return Collections.unmodifiableMap(bundles);
    }
}
