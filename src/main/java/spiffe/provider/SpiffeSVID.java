package spiffe.provider;

import spiffe.api.svid.Workload;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Represents a SPIFFE Identity
 *
 */
class SpiffeSVID {

    private static final Logger LOGGER = Logger.getLogger(SpiffeSVID.class.getName());

    /**
     * The SPIFFE Identity String
     */
    private String spiffeID;
    /**
     * The SPIFFE Verifiable Identity Document
     */
    private X509Certificate certificate;
    /**
     * The Private Key associated to the Public Key of the certificate
     */
    private PrivateKey privateKey;
    /**
     *  The trust chain used as the set of CAs trusted certificates
     */
    private Set<X509Certificate> bundle;

    /**
     * Constructor
     *
     * @param x509SVID: Workload.X509SVID
     *
     */
    SpiffeSVID(Workload.X509SVID x509SVID) {
        try {
            certificate = CertificateUtils.generateCertificate(x509SVID.getX509Svid().toByteArray());
            bundle = CertificateUtils.generateCertificates(x509SVID.getBundle().toByteArray());
            privateKey = CertificateUtils.generatePrivateKey(x509SVID.getX509SvidKey().toByteArray());
            spiffeID = x509SVID.getSpiffeId();
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "SVID message could not processed", e);
            throw new RuntimeException(e);
        }
    }

    String getSpiffeID() {
        return spiffeID;
    }

    X509Certificate getCertificate() {
        return certificate;
    }

    PrivateKey getPrivateKey() {
        return privateKey;
    }

    Set<X509Certificate> getBundle() {
        return bundle;
    }
}
