package spiffe.workloadapi;

import org.apache.commons.lang3.NotImplementedException;
import spiffe.bundle.jwtbundle.JwtBundle;
import spiffe.bundle.jwtbundle.JwtBundleSource;
import spiffe.result.Result;
import spiffe.spiffeid.SpiffeId;
import spiffe.spiffeid.TrustDomain;
import spiffe.svid.jwtsvid.JwtSvid;
import spiffe.svid.jwtsvid.JwtSvidSource;

import java.nio.file.Path;

/**
 * A <code>JwtSource</code> represents a source of SPIFFE JWT-SVID and JWT bundles
 * maintained via the Workload API.
 */
public class JwtSource implements JwtSvidSource, JwtBundleSource {

    /**
     *  Creates a new JWTSource. It blocks until the initial update
     *  has been received from the Workload API.
     *
     * @param spiffeSocketPath a Path to the Workload API endpoint
     * @return a Result containing an instance of a JwtSource, or an Error with an
     * Exception.
     */
    public static Result<JwtSource, Throwable> newSource(Path spiffeSocketPath) {
        throw new NotImplementedException("Not implemented");
    }

    @Override
    public Result<JwtBundle, String> getJwtBundleForTrustDomain(TrustDomain trustDomain) {
        throw new NotImplementedException("Not implemented");
    }

    @Override
    public Result<JwtSvid, String> FetchJwtSvid(SpiffeId subject, String audience, String... extraAudiences) {
        throw new NotImplementedException("Not implemented");
    }
}
