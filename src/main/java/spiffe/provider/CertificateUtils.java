package spiffe.provider;

import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import static java.util.Collections.EMPTY_LIST;
import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.startsWith;

/**
 * Utility class to deal with X509 Certificate creation and
 * Certificate Validation
 *
 */
class CertificateUtils {

    private static final Logger LOGGER = Logger.getLogger(SpiffeTrustManager.class.getName());

    private static final CertPathValidator CERT_PATH_VALIDATOR = getCertPathValidator();
    private static final CertificateFactory CERTIFICATE_FACTORY = getCertificateFactory();
    private static final String PRIVATE_KEY_ALGORITHM = "EC";
    private static final String SSL_SPIFFE_ACCEPT_PROPERTY = "ssl.spiffe.accept";
    private static final String SPIFFE_PREFIX = "spiffe://";
    private static final int SAN_VALUE_INDEX = 1;

    /**
     * Generate the collection of X509Certificates
     *
     * @param input as byte array
     * @return a Set of X509Certificate
     * @throws CertificateException
     */
    static List<X509Certificate> generateCertificates(byte[] input) throws CertificateException {
        Collection<? extends Certificate> certificates =  getCertificateFactory().generateCertificates(new ByteArrayInputStream(input));
        return certificates.stream()
                .map(X509Certificate.class::cast)
                .collect(Collectors.toList());
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
        KeyFactory keyFactory = KeyFactory.getInstance(PRIVATE_KEY_ALGORITHM);
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
        CertPath certPath = CERTIFICATE_FACTORY.generateCertPath(Arrays.asList(chain));
        try {
            CERT_PATH_VALIDATOR.validate(certPath, pkixParameters);
        } catch (CertPathValidatorException | InvalidAlgorithmParameterException e) {
            throw new CertificateException(e);
        }
    }

    /**
     * Validates that the SPIFFE ID is present and matches the SPIFFE ID configured in
     * the java.security property ssl.spiffe.accept
     *
     * If the authorized spiffe ids list is empty any spiffe id is authorized
     *
     * @param chain an array of X509Certificate that contains the Peer's SVID to be validated
     * @throws CertificateException when either the certificates doesn't have a SPIFFE ID or the SPIFFE ID is not authorized
     */
    static void checkSpiffeId(X509Certificate[] chain) throws CertificateException {
        Optional<String> spiffeId = getSpiffeId(chain[0]);
        if (!spiffeId.isPresent()) {
            throw new CertificateException("SPIFFE ID not found in the certificate");
        }

        List<String> acceptedSpiffeIds = getAuthorizedSpiffeIDs();

        if (!acceptedSpiffeIds.isEmpty() && !acceptedSpiffeIds.contains(spiffeId.get())) {
            String errorMessage = String.format("SPIFFE ID %s is not authorized", spiffeId.get());
            LOGGER.log(Level.WARNING, errorMessage);
            throw new CertificateException(errorMessage);
        }
    }

    /**
     * Returns the list of authorized spiffe ids configured in the SSL_SPIFFE_ACCEPT_PROPERTY property in
     * the java security properties file
     *
     */
    private static List<String> getAuthorizedSpiffeIDs() {
        String commaSeparatedSpiffeIds = Security.getProperty(SSL_SPIFFE_ACCEPT_PROPERTY);
        if (isBlank(commaSeparatedSpiffeIds)) {
            return EMPTY_LIST;
        }
        String [] array = commaSeparatedSpiffeIds.split(",");
        return normalize(Arrays.asList(array));
    }

    /**
     * Process the input list elements trimming leading and trailing blanks, returns a new list
     *
     * @param list
     * @return
     */
    private static List<String> normalize(List<String> list) {
        return list.stream().map(String::trim).collect(Collectors.toList());
    }

    /**
     * Extracts the SpiffeID from a SVID - X509Certificate
     *
     * It iterates over the list of SubjectAlternativesNames, read each entry, takes the value from the index
     * defined in SAN_VALUE_INDEX and filters the entries that starts with the SPIFFE_PREFIX and returns the first.
     *
     * @param certificate
     * @return Optional<String> with the SpiffeId
     * @throws CertificateParsingException
     */
    private static Optional<String> getSpiffeId(X509Certificate certificate) throws CertificateParsingException {
        List<String> spiffeIds = certificate.getSubjectAlternativeNames().stream()
                .map(san -> (String) san.get(SAN_VALUE_INDEX))
                .filter(uri -> startsWith(uri, SPIFFE_PREFIX))
                .collect(Collectors.toList());
        if (spiffeIds.size() > 1) {
            throw new IllegalArgumentException("Certificate contains multiple SpiffeID. Not Supported ");
        }
        return spiffeIds.stream().findFirst();
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
                    .collect(Collectors.toSet()));
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
