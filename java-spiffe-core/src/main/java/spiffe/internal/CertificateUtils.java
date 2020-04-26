package spiffe.internal;

import lombok.val;
import lombok.var;
import spiffe.spiffeid.SpiffeId;
import spiffe.spiffeid.TrustDomain;

import java.io.ByteArrayInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

import static org.apache.commons.lang3.StringUtils.startsWith;

/**
 * Common certificate utility methods.
 */
public class CertificateUtils {

    private static final String SPIFFE_PREFIX = "spiffe://";
    private static final int SAN_VALUE_INDEX = 1;
    private static final String PRIVATE_KEY_ALGORITHM = "EC";
    private static final String PUBLIC_KEY_INFRASTRUCTURE_ALGORITHM = "PKIX";
    private static final String X509_CERTIFICATE_TYPE = "X.509";

    /**
     * Generate a list of X509 certificates from a byte array.
     *
     * @param input as byte array representing a list of X509 certificates, as a DER or PEM
     * @return a List of {@link X509Certificate}
     */
    public static List<X509Certificate> generateCertificates(byte[] input) throws CertificateException {
        val certificateFactory = getCertificateFactory();

        val certificates = certificateFactory
                .generateCertificates(new ByteArrayInputStream(input));

        return certificates.stream()
                .map(X509Certificate.class::cast)
                .collect(Collectors.toList());
    }

    /**
     * Generates a private key from an array of bytes.
     *
     * @param privateKeyBytes is a PEM or DER PKCS#8 private key.
     * @return a instance of {@link PrivateKey}
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    public static PrivateKey generatePrivateKey(byte[] privateKeyBytes) throws InvalidKeySpecException, NoSuchAlgorithmException {
        PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = null;
        try {
            privateKey = generatePrivateKeyWithSpec(kspec);
        } catch (InvalidKeySpecException e) {
            byte[] keyDer = toDerFormat(privateKeyBytes);
            kspec = new PKCS8EncodedKeySpec(keyDer);
            privateKey = generatePrivateKeyWithSpec(kspec);
        }
        return privateKey;
    }

    /**
     * Validate a certificate chain with a set of trusted certificates.
     *
     * @param chain        the certificate chain
     * @param trustedCerts to validate the certificate chain
     * @throws CertificateException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws CertPathValidatorException
     */
    public static void validate(List<X509Certificate> chain, List<X509Certificate> trustedCerts) throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertPathValidatorException {
        val certificateFactory = getCertificateFactory();
        val pkixParameters = toPkixParameters(trustedCerts);
        val certPath = certificateFactory.generateCertPath(chain);
        getCertPathValidator().validate(certPath, pkixParameters);
    }

    /**
     * Extracts the SPIFE ID from a X509 certificate.
     * <p>
     * It iterates over the list of SubjectAlternativesNames, read each entry, takes the value from the index
     * defined in SAN_VALUE_INDEX and filters the entries that starts with the SPIFFE_PREFIX and returns the first.
     *
     * @param certificate a {@link X509Certificate}
     * @return an instance of a {@link SpiffeId}
     * @throws CertificateException if the certificate contains multiple SPIFFE IDs, or does not contain any, or
     *                              the SAN extension cannot be decoded
     */
    public static SpiffeId getSpiffeId(X509Certificate certificate) throws CertificateException {
        val spiffeIds = getSpiffeIds(certificate);

        if (spiffeIds.size() > 1) {
            throw new CertificateException("Certificate contains multiple SPIFFE IDs");
        }

        if (spiffeIds.size() < 1) {
            throw new CertificateException("No SPIFFE ID found in the certificate");
        }

        return SpiffeId.parse(spiffeIds.get(0));
    }

    /**
     * Extracts the trust domain of a chain of certificates.
     *
     * @param chain a list of {@link X509Certificate}
     * @return a {@link TrustDomain}
     *
     * @throws CertificateException
     */
    public static TrustDomain getTrustDomain(List<X509Certificate> chain) throws CertificateException {
        val spiffeId = getSpiffeId(chain.get(0));
        return spiffeId.getTrustDomain();
    }

    private static List<String> getSpiffeIds(X509Certificate certificate) throws CertificateParsingException {
        return certificate.getSubjectAlternativeNames()
                .stream()
                .map(san -> (String) san.get(SAN_VALUE_INDEX))
                .filter(uri -> startsWith(uri, SPIFFE_PREFIX))
                .collect(Collectors.toList());
    }

    private static PrivateKey generatePrivateKeyWithSpec(PKCS8EncodedKeySpec kspec) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory.getInstance(PRIVATE_KEY_ALGORITHM).generatePrivate(kspec);
    }

    // Create an instance of PKIXParameters used as input for the PKIX CertPathValidator
    private static PKIXParameters toPkixParameters(List<X509Certificate> trustedCerts) throws CertificateException, InvalidAlgorithmParameterException {
        if (trustedCerts == null || trustedCerts.isEmpty()) {
            throw new CertificateException("No trusted Certs");
        }

        val pkixParameters = new PKIXParameters(trustedCerts.stream()
                .map(c -> new TrustAnchor(c, null))
                .collect(Collectors.toSet()));
        pkixParameters.setRevocationEnabled(false);
        return pkixParameters;
    }

    //  Get the default PKIX CertPath Validator
    private static CertPathValidator getCertPathValidator() throws NoSuchAlgorithmException {
        return CertPathValidator.getInstance(PUBLIC_KEY_INFRASTRUCTURE_ALGORITHM);
    }

    // Get the X509 Certificate Factory
    private static CertificateFactory getCertificateFactory() throws CertificateException {
        return CertificateFactory.getInstance(X509_CERTIFICATE_TYPE);
    }

    // Given a private key in PEM format, encode it as DER
    private static byte[] toDerFormat(byte[] privateKeyPem) {
        var privateKey = new String(privateKeyPem);
        privateKey = privateKey.replaceAll("(-+BEGIN PRIVATE KEY-+\\r?\\n|-+END PRIVATE KEY-+\\r?\\n?)", "");
        privateKey = privateKey.replaceAll("\n", "");
        val decoder = Base64.getDecoder();
        return decoder.decode(privateKey);
    }

    private CertificateUtils() {}
}
