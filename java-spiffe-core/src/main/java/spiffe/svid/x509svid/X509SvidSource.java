package spiffe.svid.x509svid;

import spiffe.result.Result;

/**
 * A <code>X509SvidSource</code> represents a source of X509-SVIDs.
 */
public interface X509SvidSource {
    Result<X509Svid, String> getX509Svid();
}
