package spiffe.bundle.x509bundle;

import lombok.NonNull;
import lombok.Value;
import spiffe.result.Result;
import spiffe.spiffeid.TrustDomain;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A <code>X509BundleSet</code> represents a set of X509 Bundles keyed by TrustDomain.
 */
@Value
public class X509BundleSet implements X509BundleSource {

    ConcurrentHashMap<TrustDomain, X509Bundle> bundles;

    private X509BundleSet(final ConcurrentHashMap<TrustDomain, X509Bundle> bundles) {
        this.bundles = bundles;
    }

    /**
     * Creates a new <code>X509BundleSet</code> initialized with the bundles
     *
     * @param bundles list of bundles to put in the X509BundleSet
     * @return a X509BundleSet initialized with the list of bundles
     */
    public static X509BundleSet of(@NonNull final List<X509Bundle> bundles) {
        ConcurrentHashMap<TrustDomain, X509Bundle> bundleMap = new ConcurrentHashMap<>();
        for (X509Bundle bundle : bundles) {
            bundleMap.put(bundle.getTrustDomain(), bundle);
        }
        return new X509BundleSet(bundleMap);
    }

    /**
     * Creates a new <code>X509BundleSet</code> initialized with the x509Bundle.
     */
    public static X509BundleSet of(@NonNull final TrustDomain trustDomain, @NonNull final X509Bundle x509Bundle) {
        ConcurrentHashMap<TrustDomain, X509Bundle> bundleMap = new ConcurrentHashMap<>();
        bundleMap.put(trustDomain, x509Bundle);
        return new X509BundleSet(bundleMap);
    }

    /**
     * Adds a bundle to set, if the trustDomain already exists
     * replace the bundle.
     *
     * @param x509Bundle a X509Bundle.
     */
    public void add(@NonNull X509Bundle x509Bundle){
        bundles.put(x509Bundle.getTrustDomain(), x509Bundle);
    }

    /**
     * Returns all the bundles contained in the X509BundleSet.
     *
     * @return a list with all the bundles for all the trustDomains
     */
    public List<X509Bundle> getX509Bundles() {
        return new ArrayList<>(bundles.values());
    }

    /**
     * Returns a {@link spiffe.result.Ok} containing the X509Bundle for a trust domain,
     * if the current set doesn't have  bundle for the trust domain,
     * it returns an {@link spiffe.result.Error}.
     *
     * @param trustDomain an instance of a TrustDomain
     * @return
     */
    @Override
    public Result<X509Bundle, String> getX509BundleForTrustDomain(final TrustDomain trustDomain) {
        if (bundles.containsKey(trustDomain)) {
            return Result.ok(bundles.get(trustDomain));
        }
        return Result.error(String.format("no X.509 bundle for trust domain %s", trustDomain));
    }
}
