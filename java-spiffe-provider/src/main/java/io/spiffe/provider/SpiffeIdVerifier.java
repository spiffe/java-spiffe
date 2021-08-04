package io.spiffe.provider;

import io.spiffe.spiffeid.SpiffeId;

public interface SpiffeIdVerifier {
    /**
     * Verify that the SPIFFE ID is acceptable.
     *
     * @param spiffeId the peer SPIFFE ID
     * @return true if the SPIFFE ID is acceptable
     */
    public boolean verify(SpiffeId spiffeId);
}
