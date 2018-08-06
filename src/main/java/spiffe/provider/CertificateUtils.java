package spiffe.provider;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collection;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Arrays.asList;
import static java.lang.String.format;
import static java.util.stream.Collectors.toSet;
import static org.apache.commons.lang3.StringUtils.startsWith;

/**
 * Utility class to deal with X509 Certificate creation and
 * Certificate Validation
 *
 */
class CertificateUtils {

    private static final Logger LOGGER = Logger.getLogger(SpiffeTrustManager.class.getName());

    private static final CertPathValidator certPathValidator = getCertPathValidator();
    private static final CertificateFactory certificateFactory = getCertificateFactory();

    /**
     * Generate the collection of X509Certificates
     *
     * @param input as byte array
     * @return a Set of X509Certificate
     * @throws CertificateException
     */
    static Set<X509Certificate> generateCertificates(byte[] input) throws CertificateException {
        Collection<? extends Certificate> certificates =  getCertificateFactory().generateCertificates(new ByteArrayInputStream(input));
        return certificates.stream().map(c -> (X509Certificate) c).collect(toSet());
    }

    /**
     * Generate a single X509Certificate
     *
     * @param input as byte array
     * @return an instance of X509Certificate
     * @throws CertificateException
     */
    static X509Certificate generateCertificate(byte[] input) throws CertificateException {
        return (X509Certificate) getCertificateFactory().generateCertificate(new ByteArrayInputStream(input));
    }

    /**
     * Generates a PrivateKey from the X509SVIDKey ByteArray
     *
     * It uses PKCS8EncodedKeySpec that represents the ASN.1 encoding of a private key
     *
     * @param input as byte array
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    static PrivateKey generatePrivateKey(byte[] input) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(input));
    }

    /**
     * Validate a certificate chain against a set of trusted certificates.
     *
     * @param chain    certificate chain
     * @param trustedCerts
     * @throws CertificateException
     */
    static void validate(X509Certificate[] chain, Set<X509Certificate> trustedCerts) throws CertificateException {
        PKIXParameters pkixParameters = toPkixParameters(trustedCerts);
        CertPath certPath = certificateFactory.generateCertPath(asList(chain));
        try {
            certPathValidator.validate(certPath, pkixParameters);
        } catch (CertPathValidatorException | InvalidAlgorithmParameterException e) {
            throw new CertificateException(e);
        }
    }

    /**
     * Validates that the SPIFFE ID is present and matches the SPIFFE ID configured in
     * the java.security property ssl.spiffe.accept
     *
     * @param chain an array of X509Certificate that contains the Peer's SVID to be validated
     * @throws CertificateException when either the certificates doesn't have a SPIFFE ID or the SPIFFE ID is not trusted
     */
    static void checkSpiffeId(X509Certificate[] chain) throws CertificateException {
        Optional<String> spiffeId = getSpiffeId(chain[0]);
        if (spiffeId.isPresent()) {
            String acceptedSpiffeId = Security.getProperty("ssl.spiffe.accept");

            if (!StringUtils.equals(spiffeId.get(), acceptedSpiffeId)) {
                String errorMessage = format("SPIFFE ID %s is not a trusted", spiffeId.get());
                LOGGER.log(Level.WARNING, errorMessage);
                throw new CertificateException(errorMessage);
            }
        } else {
            throw new CertificateException("SPIFFE ID not found in the certificate");
        }
    }


    /**
     * Extracts the SpiffeID from a SVID - X509Certificate
     *
     * @param certificate
     * @return
     * @throws CertificateParsingException
     */
    private static Optional<String> getSpiffeId(X509Certificate certificate) throws CertificateParsingException {
        return certificate.getSubjectAlternativeNames().stream()
                .map(san -> (String) san.get(1))
                .filter(uri -> startsWith(uri, "spiffe://"))
                .findFirst();
    }


    /**
     * Create an instance of PKIXParameters used as input for the PKIX CertPathValidator
     *
     * @param trustedCerts
     * @return
     * @throws CertificateException
     */
    private static PKIXParameters toPkixParameters(Set<X509Certificate> trustedCerts) throws CertificateException {
        try {
            if (trustedCerts == null || trustedCerts.size() == 0) {
                throw new CertificateException("No trusted Certs");
            }

            PKIXParameters pkixParameters = new PKIXParameters(trustedCerts.stream()
                    .map(c -> new TrustAnchor(c, null))
                    .collect(toSet()));
            pkixParameters.setRevocationEnabled(false);
            return pkixParameters;
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Get the default PKIX CertPath Validator
     *
     * @return instance of CertPathValidator
     */
    private static CertPathValidator getCertPathValidator() {
        try {
            return CertPathValidator.getInstance(SpiffeProviderConstants.PUBLIC_KEY_INFRASTRUCTURE_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Get the X509 Certificate Factory
     *
     * @return instance of CertificateFactory
     */
    private static CertificateFactory getCertificateFactory() {
        try {
            return CertificateFactory.getInstance(SpiffeProviderConstants.X509_CERTIFICATE_TYPE);
        } catch (CertificateException e) {
            throw new IllegalStateException(e);
        }
    }
}
