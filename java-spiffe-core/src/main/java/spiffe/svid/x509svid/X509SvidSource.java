package spiffe.svid.x509svid;

/**
 * A <code>X509SvidSource</code> represents a source of X509-SVIDs.
 */
public interface X509SvidSource {
    X509Svid getX509Svid();
}
