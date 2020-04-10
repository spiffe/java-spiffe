package spiffe.bundle.jwtbundle;

import lombok.NonNull;
import lombok.Value;
import org.apache.commons.lang3.NotImplementedException;
import spiffe.spiffeid.TrustDomain;

import java.util.*;

/**
 * A <code>JwtBundleSet</code> represents a set of X509Bundles keyed by TrustDomain.
 */
@Value
public class JwtBundleSet implements JwtBundleSource {

    Map<TrustDomain, JwtBundle> bundles;

    private JwtBundleSet(Map<TrustDomain, JwtBundle> bundles) {
        this.bundles = bundles;
    }

    public static JwtBundleSet of(@NonNull final Map<TrustDomain, JwtBundle> bundles) {
        return new JwtBundleSet(bundles);
    }

    public static JwtBundleSet of(@NonNull final TrustDomain trustDomain,
                                  @NonNull final JwtBundle jwtBundle) {
        Map<TrustDomain, JwtBundle> bundleMap = new HashMap<>();
        bundleMap.put(trustDomain, jwtBundle);
        return new JwtBundleSet(bundleMap);
    }

    public List<JwtBundle> getJwtBundles() {
        return new ArrayList<>(bundles.values());
    }

    @Override
    public Optional<JwtBundle> getJwtBundleForTrustDomain(final TrustDomain trustDomain) {
        return Optional.ofNullable(bundles.get(trustDomain));
    }

    /**
     * Add bundle to set, if the trustDomain already exists
     * replace the bundle.
     *
     * @param jwtBundle an instance of a JwtBundle.
     */
    public void add(JwtBundle jwtBundle){
        throw new NotImplementedException("Not implemented");
    }
}
