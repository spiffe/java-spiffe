package spiffe.bundle.jwtbundle;

import lombok.NonNull;
import lombok.Value;
import lombok.val;
import org.apache.commons.lang3.NotImplementedException;
import spiffe.exception.BundleNotFoundException;
import spiffe.spiffeid.TrustDomain;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A <code>JwtBundleSet</code> represents a set of JWT bundles keyed by trust domain.
 */
@Value
public class JwtBundleSet implements JwtBundleSource {

    ConcurrentHashMap<TrustDomain, JwtBundle> bundles;

    private JwtBundleSet(ConcurrentHashMap<TrustDomain, JwtBundle> bundles) {
        this.bundles = bundles;
    }

    /**
     * Creates a JWT bundle set from the list of JWT bundles.
     *
     * @param bundles List of {@link JwtBundle}
     * @return a {@link JwtBundleSet}
     */
    public static JwtBundleSet of(@NonNull final List<JwtBundle> bundles) {
        throw new NotImplementedException("Not implemented");
    }

    /**
     * Gets the JWT bundle associated to a trust domain.
     *
     * @param trustDomain an instance of a {@link TrustDomain}
     * @return a {@link JwtBundle} associated to the given trust domain
     * @throws BundleNotFoundException if no bundle could be found for the given trust domain
     */
    @Override
    public JwtBundle getJwtBundleForTrustDomain(final TrustDomain trustDomain) throws BundleNotFoundException {
        val bundle = bundles.get(trustDomain);
        if (bundle == null) {
            throw new BundleNotFoundException(String.format("No JWT bundle for trust domain %s", trustDomain));
        }
        return bundles.get(trustDomain);
    }

    /**
     * Add JWT bundle to this set, if the trust domain already exists
     * replace the bundle.
     *
     * @param jwtBundle an instance of a JwtBundle.
     */
    public void add(JwtBundle jwtBundle){
        throw new NotImplementedException("Not implemented");
    }
}
