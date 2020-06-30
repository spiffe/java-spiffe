package io.spiffe.internal;

import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import lombok.NonNull;
import lombok.val;

import java.io.ByteArrayInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static io.spiffe.internal.KeyUsage.CRL_SIGN;
import static io.spiffe.internal.KeyUsage.DIGITAL_SIGNATURE;
import static io.spiffe.internal.KeyUsage.KEY_CERT_SIGN;
import static io.spiffe.internal.AsymmetricKeyAlgorithm.EC;
import static io.spiffe.internal.AsymmetricKeyAlgorithm.RSA;
import static org.apache.commons.lang3.StringUtils.startsWith;

/**
 * Common certificate utility methods.
 */
public class CertificateUtils {

    // Algorithms for verifying private and public keys
    private static final String SHA_512_WITH_ECDSA = "SHA512withECDSA";
    private static final String SHA_512_WITH_RSA = "SHA512withRSA";

    private static final String SPIFFE_PREFIX = "spiffe://";
    private static final int SAN_VALUE_INDEX = 1;
    private static final String PUBLIC_KEY_INFRASTRUCTURE_ALGORITHM = "PKIX";
    private static final String X509_CERTIFICATE_TYPE = "X.509";

    private CertificateUtils() {
    }

    /**
     * Generate a list of X.509 certificates from a byte array.
     *
     * @param input as byte array representing a list of X.509 certificates, as a DER or PEM
     * @return a List of {@link X509Certificate}
     */
    public static List<X509Certificate> generateCertificates(@NonNull final byte[] input) throws CertificateParsingException {
        if (input.length == 0) {
            throw new CertificateParsingException("No certificates found");
        }

        val certificateFactory = getCertificateFactory();

        Collection<? extends Certificate> certificates;
        try {
            certificates = certificateFactory.generateCertificates(new ByteArrayInputStream(input));
        } catch (CertificateException e) {
            throw new CertificateParsingException("Certificate could not be parsed from cert bytes", e);
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
    public static PrivateKey generatePrivateKey(final byte[] privateKeyBytes, AsymmetricKeyAlgorithm algorithm, KeyFileFormat keyFileFormat) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
        EncodedKeySpec kspec = getEncodedKeySpec(privateKeyBytes, keyFileFormat);
        return generatePrivateKeyWithSpec(kspec, algorithm);
    }

    /**
     * Validate a certificate chain with a set of trusted certificates.
     *
     * @param chain        the certificate chain
     * @param trustedCerts to validate the certificate chain
     * @throws CertificateException
     * @throws CertPathValidatorException
     */
    public static void validate(final List<X509Certificate> chain, final Collection<X509Certificate> trustedCerts) throws CertificateException, CertPathValidatorException {
        val certificateFactory = getCertificateFactory();
        PKIXParameters pkixParameters;
        try {
            pkixParameters = toPkixParameters(trustedCerts);
            val certPath = certificateFactory.generateCertPath(chain);
            getCertPathValidator().validate(certPath, pkixParameters);
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            throw new CertificateException(e);
        }
    }

    /**
     * Extracts the SPIFFE ID from an X.509 certificate.
     * <p>
     * It iterates over the list of SubjectAlternativesNames, read each entry, takes the value from the index
     * defined in SAN_VALUE_INDEX and filters the entries that starts with the SPIFFE_PREFIX and returns the first.
     *
     * @param certificate a {@link X509Certificate}
     * @return an instance of a {@link SpiffeId}
     * @throws CertificateException if the certificate contains multiple SPIFFE IDs, or does not contain any, or
     *                              the SAN extension cannot be decoded
     */
    public static SpiffeId getSpiffeId(final X509Certificate certificate) throws CertificateException {
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
    public static TrustDomain getTrustDomain(final List<X509Certificate> chain) throws CertificateException {
        val spiffeId = getSpiffeId(chain.get(0));
        return spiffeId.getTrustDomain();
    }

    /**
     * Validates that the private key and the public key in the x509Certificate match by
     * creating a signature with the private key and verifying with the public key.
     *
     * @throws InvalidKeyException if the keys don't match
     */
    public static void validatePrivateKey(final PrivateKey privateKey, final X509Certificate x509Certificate) throws InvalidKeyException {
        AsymmetricKeyAlgorithm algorithm = AsymmetricKeyAlgorithm.parse(privateKey.getAlgorithm());

        switch (algorithm) {
            case RSA:
                verifyKeys(privateKey, x509Certificate.getPublicKey(), SHA_512_WITH_RSA);
                break;
            case EC:
                verifyKeys(privateKey, x509Certificate.getPublicKey(), SHA_512_WITH_ECDSA);
                break;
            default:
                throw new InvalidKeyException(String.format("Private Key algorithm not supported: %s", algorithm));
        }
    }

    public static boolean isCA(final X509Certificate cert) {
        return cert.getBasicConstraints() != -1;
    }

    public static boolean hasKeyUsageCertSign(final X509Certificate cert) {
        boolean[] keyUsage = cert.getKeyUsage();
        return keyUsage[KEY_CERT_SIGN.index()];
    }

    public static boolean hasKeyUsageDigitalSignature(final X509Certificate cert) {
        boolean[] keyUsage = cert.getKeyUsage();
        return keyUsage[DIGITAL_SIGNATURE.index()];
    }

    public static boolean hasKeyUsageCRLSign(final X509Certificate cert) {
        boolean[] keyUsage = cert.getKeyUsage();
        return keyUsage[CRL_SIGN.index()];
    }

    private static EncodedKeySpec getEncodedKeySpec(final byte[] privateKeyBytes, KeyFileFormat keyFileFormat) throws InvalidKeyException {
        EncodedKeySpec keySpec;
        if (keyFileFormat == KeyFileFormat.PEM) {
            byte[] keyDer = toDerFormat(privateKeyBytes);
            keySpec = new PKCS8EncodedKeySpec(keyDer);
        } else {
            keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        }
        return keySpec;
    }

    private static void verifyKeys(final PrivateKey privateKey, final PublicKey publicKey, final String algorithm) throws InvalidKeyException {
        final byte[] challenge = new SecureRandom().generateSeed(100);
        try {
            Signature sig = Signature.getInstance(algorithm);
            sig.initSign(privateKey);
            sig.update(challenge);
            byte[] signature = sig.sign();
            sig.initVerify(publicKey);
            sig.update(challenge);
            if (!sig.verify(signature)) {
                throw new InvalidKeyException("Private Key does not match Certificate Public Key");
            }
        } catch (NoSuchAlgorithmException | SignatureException e) {
            throw new InvalidKeyException("Private and Public Keys could not be verified", e);
        }
    }

    private static List<String> getSpiffeIds(final X509Certificate certificate) throws CertificateParsingException {
        if (certificate.getSubjectAlternativeNames() == null) {
            return Collections.emptyList();
        }
        return certificate.getSubjectAlternativeNames()
                .stream()
                .map(san -> (String) san.get(SAN_VALUE_INDEX))
                .filter(uri -> startsWith(uri, SPIFFE_PREFIX))
                .collect(Collectors.toList());
    }

    private static PrivateKey generatePrivateKeyWithSpec(final EncodedKeySpec keySpec, AsymmetricKeyAlgorithm algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PrivateKey privateKey;
        switch (algorithm) {
            case EC:
                privateKey = KeyFactory.getInstance(EC.value()).generatePrivate(keySpec);
                break;
            case RSA:
                privateKey = KeyFactory.getInstance(RSA.value()).generatePrivate(keySpec);
                break;
            default:
                throw new NoSuchAlgorithmException(String.format("Private Key algorithm is not supported: %s", algorithm));
        }
        return privateKey;
    }

    // Create an instance of PKIXParameters used as input for the PKIX CertPathValidator
    private static PKIXParameters toPkixParameters(final Collection<X509Certificate> trustedCerts) throws CertificateException, InvalidAlgorithmParameterException {
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
    private static CertificateFactory getCertificateFactory() {
        try {
            return CertificateFactory.getInstance(X509_CERTIFICATE_TYPE);
        } catch (CertificateException e) {
            throw new IllegalStateException("Could not create Certificate Factory", e);
        }
    }

    // Given a private key in PEM format, encode it as DER
    private static byte[] toDerFormat(final byte[] privateKeyPem) throws InvalidKeyException {
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
}
