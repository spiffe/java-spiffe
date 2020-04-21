package spiffe.internal;

import lombok.val;
import org.apache.commons.lang3.exception.ExceptionUtils;
import spiffe.result.Result;
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
import java.util.ArrayList;
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
     * Generate a List of X509Certificates from a byte array.
     *
     * @param input as byte array representing a list of X509Certificates, as a DER or PEM
     * @return a List of X509Certificate
     */
    public static Result<List<X509Certificate>, String> generateCertificates(byte[] input) {
        val certificateFactory = getCertificateFactory();
        if (certificateFactory.isError()) {
            return Result.error("Error parsing certificates: could not create certificate factory %s", certificateFactory.getError());
        }

        try {
            val certificates = certificateFactory
                    .getValue()
                    .generateCertificates(new ByteArrayInputStream(input));

            val x509CertificateList = certificates.stream()
                    .map(X509Certificate.class::cast)
                    .collect(Collectors.toList());

            return Result.ok(x509CertificateList);
        } catch (CertificateException e) {
            return Result.error("Error parsing certificates: %s", e.getMessage());
        }
    }

    /**
     * Generates a PrivateKey from an array of bytes.
     *
     * @param privateKeyBytes is a PEM or DER PKCS#8 Private Key.
     * @return a Result {@link spiffe.result.Ok} containing a {@link PrivateKey} or an {@link spiffe.result.Error}.
     */
    public static Result<PrivateKey, String> generatePrivateKey(byte[] privateKeyBytes) {
        PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(privateKeyBytes);
        Result<PrivateKey, Throwable> privateKeyResult = generatePrivateKeyWithSpec(kspec);

        if (privateKeyResult.isOk()) {
            return Result.ok(privateKeyResult.getValue());
        }

        // PrivateKey is in PEM format, not supported, need to convert to DER and try again
        if (privateKeyResult.getError() instanceof InvalidKeySpecException) {
            byte[] keyDer = toDerFormat(privateKeyBytes);
            kspec= new PKCS8EncodedKeySpec(keyDer);
            privateKeyResult = generatePrivateKeyWithSpec(kspec);
        }
        return Result.ok(privateKeyResult.getValue());
    }

    private static Result<PrivateKey, Throwable> generatePrivateKeyWithSpec(PKCS8EncodedKeySpec kspec) {
        try {
            val keyFactory = KeyFactory.getInstance(PRIVATE_KEY_ALGORITHM);
            val privateKey = keyFactory.generatePrivate(kspec);
            return Result.ok(privateKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            return Result.error(e);
        }
    }

    /**
     * Validate a certificate chain against a set of trusted certificates.
     *
     * @param chain the certificate chain
     * @param trustedCerts to validate the certificate chain
     * @return a Result {@link spiffe.result.Ok} if the chain can be chained to any of the trustedCerts, or
     * an {@link spiffe.result.Error}.
     *
     */
    public static Result<Boolean, String> validate(List<X509Certificate> chain, List<X509Certificate> trustedCerts) {
        val certificateFactory = getCertificateFactory();
        if (certificateFactory.isError()) {
            return Result.error(certificateFactory.getError());
        }

        try {
            PKIXParameters pkixParameters = toPkixParameters(trustedCerts);
            val certPath = certificateFactory.getValue().generateCertPath(chain);
            getCertPathValidator().validate(certPath, pkixParameters);
        } catch (CertificateException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | CertPathValidatorException e) {
            return Result.error("Error validating certificate chain: %s %n %s", e.getMessage(), ExceptionUtils.getStackTrace(e));
        }

        return Result.ok(true);
    }

    /**
     * Extracts the SpiffeID from a SVID - X509Certificate.
     * <p>
     * It iterates over the list of SubjectAlternativesNames, read each entry, takes the value from the index
     * defined in SAN_VALUE_INDEX and filters the entries that starts with the SPIFFE_PREFIX and returns the first.
     *
     * @param certificate a X509Certificate
     * @return spiffe.result.Result with the SpiffeId
     * @throws RuntimeException         when the certificate subjectAlternatives names cannot be read
     * @throws IllegalArgumentException when the certificate contains multiple SpiffeId.
     */
    public static Result<SpiffeId, String> getSpiffeId(X509Certificate certificate) {
        val spiffeIds = getSpiffeIds(certificate);

        if (spiffeIds.size() > 1) {
            return Result.error("Certificate contains multiple SPIFFE IDs.");
        }

        if (spiffeIds.size() < 1) {
            return Result.error("No SPIFFE ID found in the certificate.");
        }

        val spiffeId = SpiffeId.parse(spiffeIds.get(0));
        if (spiffeId.isError()) {
            return Result.error(spiffeId.getError());
        }
        return spiffeId;
    }

    // Extracts the trustDomain of a chain of certificates
    public static Result<TrustDomain, String> getTrustDomain(List<X509Certificate> chain) {
        val spiffeId = getSpiffeId(chain.get(0));
        if (spiffeId.isError()) {
            return Result.error(spiffeId.getError());
        }
        return Result.ok(spiffeId.getValue().getTrustDomain());
    }

    private static List<String> getSpiffeIds(X509Certificate certificate) {
        try {
            return certificate.getSubjectAlternativeNames()
                    .stream()
                    .map(san -> (String) san.get(SAN_VALUE_INDEX))
                    .filter(uri -> startsWith(uri, SPIFFE_PREFIX))
                    .collect(Collectors.toList());
        } catch (CertificateParsingException e) {
            return new ArrayList<>();
        }
    }

    // Create an instance of PKIXParameters used as input for the PKIX CertPathValidator
    private static PKIXParameters toPkixParameters(List<X509Certificate> trustedCerts) throws CertificateException, InvalidAlgorithmParameterException {
        if (trustedCerts == null || trustedCerts.size() == 0) {
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
    private static Result<CertificateFactory, String> getCertificateFactory() {
        try {
            return Result.ok(CertificateFactory.getInstance(X509_CERTIFICATE_TYPE));
        } catch (CertificateException e) {
            return Result.error("Error creating certificate factory: %s", e.getMessage());
        }
    }

    // Given a private key in PEM format, encode it as DER
    private static byte[] toDerFormat(byte[] privateKeyPem) {
        String privateKey = new String(privateKeyPem);
        privateKey = privateKey.replaceAll("(-+BEGIN PRIVATE KEY-+\\r?\\n|-+END PRIVATE KEY-+\\r?\\n?)", "");
        privateKey = privateKey.replaceAll("\n", "");
        val decoder = Base64.getDecoder();
        return decoder.decode(privateKey);
    }
}
