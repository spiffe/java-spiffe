package io.spiffe.bundle.jwtbundle;

import io.spiffe.bundle.BundleSource;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.spiffeid.TrustDomain;
import lombok.NonNull;
import lombok.Value;
import lombok.val;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Represents a set of JWT bundles keyed by trust domain.
 */
@Value
public class JwtBundleSet implements BundleSource<JwtBundle> {

    Map<TrustDomain, JwtBundle> bundles;

    private JwtBundleSet(Map<TrustDomain, JwtBundle> bundles) {
        this.bundles = new ConcurrentHashMap<>(bundles);
    }

    /**
     * Creates a JWT bundle set from the list of JWT bundles.
     *
     * @param bundles List of {@link JwtBundle}
     * @return a {@link JwtBundleSet}
     */
    public static JwtBundleSet of(@NonNull final List<JwtBundle> bundles) {
        Map<TrustDomain, JwtBundle> bundleMap = new HashMap<>();
        for (JwtBundle bundle : bundles) {
            bundleMap.put(bundle.getTrustDomain(), bundle);
        }
        return new JwtBundleSet(bundleMap);
    }

    /**
     * Gets the JWT bundle associated to a trust domain.
     *
     * @param trustDomain an instance of a {@link TrustDomain}
     * @return a {@link JwtBundle} associated to the given trust domain
     * @throws BundleNotFoundException if no bundle could be found for the given trust domain
     */
    @Override
    public JwtBundle getBundleForTrustDomain(@NonNull final TrustDomain trustDomain) throws BundleNotFoundException {
        val bundle = bundles.get(trustDomain);
        if (bundle == null) {
            throw new BundleNotFoundException(String.format("No JWT bundle for trust domain %s", trustDomain));
        }
        return bundle;
    }

    /**
     * Returns the map of JWT bundles keyed by trust domain.
     */
    public Map<TrustDomain, JwtBundle> getBundles() {
        return Collections.unmodifiableMap(bundles);
    }

    /**
     * Add JWT bundle to this set, if the trust domain already exists
     * replace the bundle.
     *
     * @param jwtBundle an instance of a JwtBundle.
     */
    public void put(@NonNull JwtBundle jwtBundle) {
        bundles.put(jwtBundle.getTrustDomain(), jwtBundle);
    }
}
