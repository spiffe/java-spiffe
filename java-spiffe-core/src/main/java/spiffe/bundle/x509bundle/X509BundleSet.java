package spiffe.bundle.x509bundle;

import lombok.Value;
import org.apache.commons.lang3.NotImplementedException;
import spiffe.spiffeid.TrustDomain;

import java.util.*;

/**
 * A <code>X509BundleSet</code> represents a set of X509 Bundles keyed by TrustDomain.
 */
@Value
public class X509BundleSet implements X509BundleSource {

    Map<TrustDomain, X509Bundle> bundles;

    private X509BundleSet(final Map<TrustDomain, X509Bundle> bundles) {
        this.bundles = bundles;
    }

    public static X509BundleSet of(final Map<TrustDomain, X509Bundle> bundles) {
        return new X509BundleSet(bundles);
    }

    public static X509BundleSet of(final TrustDomain trustDomain, final X509Bundle x509Bundle) {
        Map<TrustDomain, X509Bundle> bundleMap = new HashMap<>();
        bundleMap.put(trustDomain, x509Bundle);
        return new X509BundleSet(bundleMap);
    }

    /**
     * Adds a bundle to set, if the trustDomain already exists
     * replace the bundle.
     *
     * @param x509Bundle a X509Bundle.
     */
    public void add(X509Bundle x509Bundle){
      throw new NotImplementedException("Not implemented");
    }

    /**
     * Returns all the bundles contained in the X509BundleSet
     *
     * @return a list with all the bundles for all the trustDomains
     */
    public List<X509Bundle> getX509Bundles() {
        return new ArrayList<>(bundles.values());
    }

    @Override
    public Optional<X509Bundle> getX509BundleForTrustDomain(final TrustDomain trustDomain) {
        return Optional.ofNullable(bundles.get(trustDomain));
    }
}
