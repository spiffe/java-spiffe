package spiffe.internal;

import lombok.NonNull;
import lombok.val;
import spiffe.spiffeid.SpiffeId;
import spiffe.spiffeid.TrustDomain;

import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;

import static org.apache.commons.lang3.StringUtils.startsWith;

/**
 * Common certificate utility methods.
 */
public class CertificateUtils {

    private static final String SPIFFE_PREFIX = "spiffe://";
    private static final int SAN_VALUE_INDEX = 1;
    private static final String PUBLIC_KEY_INFRASTRUCTURE_ALGORITHM = "PKIX";
    private static final String X509_CERTIFICATE_TYPE = "X.509";

    // X509Certificate Key Usage indexes
    private static final int DIGITAL_SIGNATURE = 0;
    private static final int NON_REPUDIATION = 1;
    private static final int KEY_ENCIPHERMENT = 2;
    private static final int DATA_ENCIPHERMENT = 3;
    private static final int KEY_AGREEMENT = 4;
    private static final int KEY_CERT_SIGN = 5;
    private static final int CRL_SIGN = 6;
    private static final int ENCIPHER_ONLY = 7;
    private static final int DECIPHER_ONLY = 8;

    /**
     * Generate a list of X.509 certificates from a byte array.
     *
     * @param input as byte array representing a list of X.509 certificates, as a DER or PEM
     * @return a List of {@link X509Certificate}
     */
    public static List<X509Certificate> generateCertificates(@NonNull byte[] input) throws CertificateParsingException {
        if (input.length == 0) {
            throw new CertificateParsingException("No certificates found");
        }

        CertificateFactory certificateFactory = null;
        try {
            certificateFactory = getCertificateFactory();
        } catch (CertificateException e) {
            throw new IllegalStateException("Could not create Certificate Factory", e);
        }

        Collection<? extends Certificate> certificates;
        try {
            certificates = certificateFactory.generateCertificates(new ByteArrayInputStream(input));
        } catch (CertificateException e) {
            throw new CertificateParsingException("Certificate could not be parsed from cert bytes");
        }

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
    public static PrivateKey generatePrivateKey(byte[] privateKeyBytes) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
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
    public static void validate(List<X509Certificate> chain, List<X509Certificate> trustedCerts) throws CertificateException, CertPathValidatorException {
        val certificateFactory = getCertificateFactory();
        PKIXParameters pkixParameters = null;
        try {
            pkixParameters = toPkixParameters(trustedCerts);
            val certPath = certificateFactory.generateCertPath(chain);
            getCertPathValidator().validate(certPath, pkixParameters);
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            throw new CertificateException(e);
        }
    }

    /**
     * Extracts the SPIFE ID from a X.509 certificate.
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
            throw new CertificateException("Certificate does not contain SPIFFE ID in the URI SAN");
        }

        return SpiffeId.parse(spiffeIds.get(0));
    }

    /**
     * Extracts the trust domain of a chain of certificates.
     *
     * @param chain a list of {@link X509Certificate}
     * @return a {@link TrustDomain}
     * @throws CertificateException
     */
    public static TrustDomain getTrustDomain(List<X509Certificate> chain) throws CertificateException {
        val spiffeId = getSpiffeId(chain.get(0));
        return spiffeId.getTrustDomain();
    }

    /**
     * Validates that the private key and the public key in the x509Certificate match by
     * creating a signature with the private key and verifying with the public key.
     *
     * @throws InvalidKeyException if the keys don't match
     */
    public static void validatePrivateKey(PrivateKey privateKey, X509Certificate x509Certificate) throws InvalidKeyException {
        // create a challenge
        byte[] challenge = new byte[1000];
        ThreadLocalRandom.current().nextBytes(challenge);

        Signature sig = null;

        try {
            if ("RSA".equals(privateKey.getAlgorithm())) {
                sig = Signature.getInstance("SHA256withRSA");
            } else {
                sig = Signature.getInstance("SHA1withECDSA");
            }

            sig.initSign(privateKey);
            sig.update(challenge);
            byte[] signature = sig.sign();

            sig.initVerify(x509Certificate.getPublicKey());
            sig.update(challenge);

            if (!sig.verify(signature)) {
                throw new InvalidKeyException("Private Key does not match Certificate Public Key");
            }
        } catch (SignatureException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("Could not validate private keys", e);
        }
    }

    public static boolean isCA(X509Certificate cert) {
        return cert.getBasicConstraints() != -1;
    }

    public static boolean hasKeyUsageCertSign(X509Certificate cert) {
        boolean[] keyUsage = cert.getKeyUsage();
        return keyUsage[KEY_CERT_SIGN];
    }

    public static boolean hasKeyUsageDigitalSignature(X509Certificate cert) {
        boolean[] keyUsage = cert.getKeyUsage();
        return keyUsage[DIGITAL_SIGNATURE];
    }

    public static boolean hasKeyUsageCRLSign(X509Certificate cert) {
        boolean[] keyUsage = cert.getKeyUsage();
        return keyUsage[CRL_SIGN];
    }

    private static List<String> getSpiffeIds(X509Certificate certificate) throws CertificateParsingException {
        return certificate.getSubjectAlternativeNames()
                .stream()
                .map(san -> (String) san.get(SAN_VALUE_INDEX))
                .filter(uri -> startsWith(uri, SPIFFE_PREFIX))
                .collect(Collectors.toList());
    }

    private static PrivateKey generatePrivateKeyWithSpec(PKCS8EncodedKeySpec kspec) throws NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            return KeyFactory.getInstance("EC").generatePrivate(kspec);
        } catch (InvalidKeySpecException e) {
            return KeyFactory.getInstance("RSA").generatePrivate(kspec);
        }
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

    // Get the X.509 Certificate Factory
    private static CertificateFactory getCertificateFactory() throws CertificateException {
        return CertificateFactory.getInstance(X509_CERTIFICATE_TYPE);
    }

    // Given a private key in PEM format, encode it as DER
    private static byte[] toDerFormat(byte[] privateKeyPem) throws InvalidKeyException {
        String privateKeyAsString = new String(privateKeyPem);
        privateKeyAsString = privateKeyAsString.replaceAll("(-+BEGIN PRIVATE KEY-+\\r?\\n|-+END PRIVATE KEY-+\\r?\\n?)", "");
        privateKeyAsString = privateKeyAsString.replaceAll("\n", "");
        val decoder = Base64.getDecoder();
        try {
            return decoder.decode(privateKeyAsString);
        } catch (Exception e) {
            throw new InvalidKeyException(e);
        }
    }

    private CertificateUtils() {
    }
}
