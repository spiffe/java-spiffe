package io.spiffe.provider;

import io.spiffe.spiffeid.SpiffeId;

import java.security.cert.X509Certificate;

public interface SpiffeIdVerifier {
    /**
     * Verify that an X509-SVID is acceptable. This method receives the SPIFFE ID of the SVID and the certificate
     * chain.
     *
     * @param spiffeId the SPIFFE ID of the SVID
     * @param verifiedChain the certificate chain with the X509-SVID certificate back to an X.509 root for the trust domain.
     * @return true if the SPIFFE ID is acceptable
     */
    public boolean verify(SpiffeId spiffeId, X509Certificate[] verifiedChain);
}
