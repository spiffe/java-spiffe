package spiffe.bundle.x509bundle;

import lombok.NonNull;
import lombok.Value;
import spiffe.exception.BundleNotFoundException;
import spiffe.spiffeid.TrustDomain;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A <code>X509BundleSet</code> represents a set of X.509 bundles keyed by trust domain.
 */
@Value
public class X509BundleSet implements X509BundleSource {

    ConcurrentHashMap<TrustDomain, X509Bundle> bundles;

    private X509BundleSet(final ConcurrentHashMap<TrustDomain, X509Bundle> bundles) {
        this.bundles = bundles;
    }

    /**
     * Creates a new X.509 bundle set from a list of X.509 bundles.
     *
     * @param bundles a list of {@link X509Bundle}
     * @return a {@link X509BundleSet} initialized with the list of bundles
     */
    public static X509BundleSet of(@NonNull final List<X509Bundle> bundles) {
        ConcurrentHashMap<TrustDomain, X509Bundle> bundleMap = new ConcurrentHashMap<>();
        for (X509Bundle bundle : bundles) {
            bundleMap.put(bundle.getTrustDomain(), bundle);
        }
        return new X509BundleSet(bundleMap);
    }

    /**
     * Adds a bundle to this Set, if the trust domain already exists,
     * replaces the bundle.
     *
     * @param x509Bundle a {@link X509Bundle}
     */
    public void add(@NonNull X509Bundle x509Bundle){
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
    public X509Bundle getX509BundleForTrustDomain(final TrustDomain trustDomain) throws BundleNotFoundException {
        if (bundles.containsKey(trustDomain)) {
            return bundles.get(trustDomain);
        }
        throw new BundleNotFoundException(String.format("No X509 bundle for trust domain %s", trustDomain));
    }
}
