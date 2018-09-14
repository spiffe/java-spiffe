package spiffe.provider;

import com.google.protobuf.ByteString;
import spiffe.api.svid.Workload;

import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Represents a SPIFFE Identity
 *
 */
public class SpiffeSVID {

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
     *  The map of Federated Trust Domains and their bundles
     */
    private Map<String, Set<X509Certificate>> federatedBundles;

    /**
     *  All trusted CAs certs, including the Federated CAs
     */
    private Set<X509Certificate> trustedCerts;

    /**
     * Constructor
     *
     * @param x509SVIDResponse: Workload.X509SVIDResponse
     *
     */
    SpiffeSVID(Workload.X509SVIDResponse x509SVIDResponse) {
        try {

            Workload.X509SVID svid  = x509SVIDResponse.getSvidsList().get(0);

            certificate = CertificateUtils.generateCertificate(svid.getX509Svid().toByteArray());
            bundle = CertificateUtils.generateCertificates(svid.getBundle().toByteArray());
            privateKey = CertificateUtils.generatePrivateKey(svid.getX509SvidKey().toByteArray());
            spiffeID = svid.getSpiffeId();
            federatedBundles = buildFederatedX509CertificatesMap(x509SVIDResponse.getFederatedBundlesMap());

            trustedCerts = new HashSet<>();
            trustedCerts.addAll(bundle);
            federatedBundles.values().forEach(set -> trustedCerts.addAll(set));
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "SVID message could not be processed", e);
            throw new RuntimeException(e);
        }
    }

    private Map<String, Set<X509Certificate>> buildFederatedX509CertificatesMap(Map<String, ByteString> federatedBundlesMap) {
        Map<String, Set<X509Certificate>> federatedCertificates = new HashMap<>();
        federatedBundlesMap.forEach((trustDomain, cert) -> {
            try {
                federatedCertificates.put(trustDomain, CertificateUtils.generateCertificates(cert.toByteArray()));
            } catch (CertificateException e) {
                LOGGER.log(Level.SEVERE, "Federated Bundles couldn't be processed ", e);
                throw new RuntimeException(e);
            }
        });
        return federatedCertificates;
    }

    public String getSpiffeID() {
        return spiffeID;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public Set<X509Certificate> getBundle() {
        return bundle;
    }

    public Map<String, Set<X509Certificate>> getFederatedBundles() {
        return federatedBundles;
    }

    public Set<X509Certificate> getTrustedCerts() {
        return trustedCerts;
    }
}
