package spiffe.bundle.jwtbundle;

import lombok.NonNull;
import lombok.Value;
import org.apache.commons.lang3.NotImplementedException;
import spiffe.result.Result;
import spiffe.spiffeid.TrustDomain;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A <code>JwtBundleSet</code> represents a set of X509Bundles keyed by TrustDomain.
 */
@Value
public class JwtBundleSet implements JwtBundleSource {

    ConcurrentHashMap<TrustDomain, JwtBundle> bundles;

    private JwtBundleSet(ConcurrentHashMap<TrustDomain, JwtBundle> bundles) {
        this.bundles = bundles;
    }

    public static JwtBundleSet of(@NonNull final List<JwtBundle> bundles) {
        throw new NotImplementedException("Not implemented");
    }

    public static JwtBundleSet of(@NonNull final TrustDomain trustDomain,
                                  @NonNull final JwtBundle jwtBundle) {
        throw new NotImplementedException("Not implemented");
    }

    public List<JwtBundle> getJwtBundles() {
        return new ArrayList<>(bundles.values());
    }

    @Override
    public Result<JwtBundle, String> getJwtBundleForTrustDomain(final TrustDomain trustDomain) {
        if (bundles.containsKey(trustDomain)) {
            return Result.ok(bundles.get(trustDomain));
        }
        return Result.error("No JWT bundle for trust domain %s", trustDomain);
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
