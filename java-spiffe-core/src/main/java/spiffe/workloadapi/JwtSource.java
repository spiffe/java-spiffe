package spiffe.workloadapi;

import org.apache.commons.lang3.NotImplementedException;
import spiffe.bundle.jwtbundle.JwtBundle;
import spiffe.bundle.jwtbundle.JwtBundleSource;
import spiffe.spiffeid.SpiffeId;
import spiffe.spiffeid.TrustDomain;
import spiffe.svid.jwtsvid.JwtSvid;
import spiffe.svid.jwtsvid.JwtSvidSource;

/**
 * A <code>JwtSource</code> represents a source of SPIFFE JWT SVID and JWT bundles
 * maintained via the Workload API.
 */
public class JwtSource implements JwtSvidSource, JwtBundleSource {

    /**
     *  Creates a new JWT source. It blocks until the initial update
     *  has been received from the Workload API.
     *
     * @param spiffeSocketPath a path to the Workload API endpoint
     * @return an instance of a {@link JwtSource}
     */
    public static JwtSource newSource(String spiffeSocketPath) {
        throw new NotImplementedException("Not implemented");
    }

    @Override
    public JwtBundle getJwtBundleForTrustDomain(TrustDomain trustDomain) {
        throw new NotImplementedException("Not implemented");
    }

    @Override
    public JwtSvid FetchJwtSvid(SpiffeId subject, String audience, String... extraAudiences) {
        throw new NotImplementedException("Not implemented");
    }
}
