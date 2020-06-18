package io.spiffe.svid.x509svid;

/**
 * Represents a source of X.509 SVIDs.
 */
public interface X509SvidSource {

    /**
     * Returns the X.509 SVID in the source.
     *
     * @return an instance of a {@link X509Svid}
     */
    X509Svid getX509Svid();
}
