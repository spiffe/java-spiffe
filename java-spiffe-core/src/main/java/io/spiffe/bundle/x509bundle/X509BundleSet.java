package io.spiffe.bundle.x509bundle;

import io.spiffe.bundle.BundleSource;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.spiffeid.TrustDomain;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Represents a set of X.509 bundles keyed by trust domain.
 */
public final class X509BundleSet implements BundleSource<X509Bundle> {

    private final Map<TrustDomain, X509Bundle> bundles;

    private X509BundleSet(Map<TrustDomain, X509Bundle> bundles) {
        this.bundles = new ConcurrentHashMap<>(bundles);
    }

    private X509BundleSet() {
        this.bundles = new ConcurrentHashMap<>();
    }

    /**
     * Creates a new X.509 bundle set from a list of X.509 bundles.
     *
     * @param bundles Collection of {@link X509Bundle}
     * @return a {@link X509BundleSet} initialized with the list of bundles
     */
    public static X509BundleSet of(Collection<X509Bundle> bundles) {
        Objects.requireNonNull(bundles, "bundles must not be null");
        
        if (bundles.size() == 0) {
            throw new IllegalArgumentException("X509Bundles collection is empty");
        }

        final Map<TrustDomain, X509Bundle> bundleMap = new ConcurrentHashMap<>();
        for (X509Bundle bundle : bundles) {
            bundleMap.put(bundle.getTrustDomain(), bundle);
        }
        return new X509BundleSet(bundleMap);
    }

    /**
     * Creates a new X.509 bundle empty.
     *
     * @return a {@link X509BundleSet}
     */
    public static X509BundleSet emptySet() {
        return new X509BundleSet();
    }

    /**
     * Adds an X.509 bundle to this Set, if the trust domain already exists,
     * replaces the bundle.
     *
     * @param x509Bundle a {@link X509Bundle}
     */
    public void put(X509Bundle x509Bundle) {
        Objects.requireNonNull(x509Bundle, "x509Bundle must not be null");
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
    public X509Bundle getBundleForTrustDomain(TrustDomain trustDomain) throws BundleNotFoundException {
        Objects.requireNonNull(trustDomain, "trustDomain must not be null");

        X509Bundle bundle = bundles.get(trustDomain);
        if (bundle == null) {
            throw new BundleNotFoundException(
                    String.format("No X.509 bundle for trust domain %s", trustDomain)
            );
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

    // -------- equals, hashCode, toString (replacement for @Value) --------

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof X509BundleSet)) return false;
        X509BundleSet that = (X509BundleSet) o;
        return Objects.equals(bundles, that.bundles);
    }

    @Override
    public int hashCode() {
        return Objects.hash(bundles);
    }

    @Override
    public String toString() {
        return "X509BundleSet{" +
                "bundles=" + bundles +
                '}';
    }
}
