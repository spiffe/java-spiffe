package io.spiffe.bundle.jwtbundle;

import io.spiffe.bundle.BundleSource;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.spiffeid.TrustDomain;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Represents a set of JWT bundles keyed by trust domain.
 */
public final class JwtBundleSet implements BundleSource<JwtBundle> {

    private final Map<TrustDomain, JwtBundle> bundles;

    private JwtBundleSet(final Map<TrustDomain, JwtBundle> bundles) {
        this.bundles = new ConcurrentHashMap<>(bundles);
    }

    private JwtBundleSet() {
        this.bundles = new ConcurrentHashMap<>();
    }

    /**
     * Creates a JWT bundle set from the list of JWT bundles.
     *
     * @param bundles Collection of {@link JwtBundle}
     * @return a {@link JwtBundleSet}
     */
    public static JwtBundleSet of(Collection<JwtBundle> bundles) {
        Objects.requireNonNull(bundles, "bundles must not be null");

        if (bundles.size() == 0) {
            throw new IllegalArgumentException("JwtBundle collection is empty");
        }
        final Map<TrustDomain, JwtBundle> bundleMap = new ConcurrentHashMap<>();
        for (JwtBundle bundle : bundles) {
            Objects.requireNonNull(bundle, "bundle must not be null");
            bundleMap.put(bundle.getTrustDomain(), bundle);
        }
        return new JwtBundleSet(bundleMap);
    }

    /**
     * Creates a JWT bundle set empty.
     *
     * @return a {@link JwtBundleSet}
     */
    public static JwtBundleSet emptySet() {
        return new JwtBundleSet();
    }

    /**
     * Gets the JWT bundle associated to a trust domain.
     *
     * @param trustDomain an instance of a {@link TrustDomain}
     * @return a {@link JwtBundle} associated to the given trust domain
     * @throws BundleNotFoundException if no bundle could be found for the given trust domain
     */
    @Override
    public JwtBundle getBundleForTrustDomain(TrustDomain trustDomain) throws BundleNotFoundException {
        Objects.requireNonNull(trustDomain, "trustDomain must not be null");

        JwtBundle bundle = bundles.get(trustDomain);
        if (bundle == null) {
            throw new BundleNotFoundException(String.format("No JWT bundle for trust domain %s", trustDomain));
        }
        return bundle;
    }

    /**
     * Returns the map of JWT bundles keyed by trust domain.
     *
     * @return the map of JWT bundles keyed by trust domain
     */
    public Map<TrustDomain, JwtBundle> getBundles() {
        return Collections.unmodifiableMap(bundles);
    }

    /**
     * Adds JWT bundle to this set, if the trust domain already exists
     * replace the bundle.
     *
     * @param jwtBundle an instance of a JwtBundle.
     */
    public void put(JwtBundle jwtBundle) {
        Objects.requireNonNull(jwtBundle, "jwtBundle must not be null");
        bundles.put(jwtBundle.getTrustDomain(), jwtBundle);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof JwtBundleSet)) return false;
        JwtBundleSet that = (JwtBundleSet) o;
        return Objects.equals(bundles, that.bundles);
    }

    @Override
    public int hashCode() {
        return Objects.hash(bundles);
    }

    @Override
    public String toString() {
        return "JwtBundleSet(" +
                "bundles=" + bundles +
                ')';
    }
}
