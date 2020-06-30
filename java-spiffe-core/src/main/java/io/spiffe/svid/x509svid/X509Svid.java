package io.spiffe.svid.x509svid;

import io.spiffe.exception.X509SvidException;
import io.spiffe.internal.AsymmetricKeyAlgorithm;
import io.spiffe.internal.CertificateUtils;
import io.spiffe.internal.KeyFileFormat;
import io.spiffe.spiffeid.SpiffeId;
import lombok.NonNull;
import lombok.Value;
import lombok.val;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.List;

/**
 * Represents a SPIFFE X.509 SVID.
 * <p>
 * Contains a SPIFFE ID, a private key and a chain of X.509 certificates.
 */
@Value
public class X509Svid {

    SpiffeId spiffeId;

    /**
     * The X.509 certificates of the X.509-SVID. The leaf certificate is
     * the X.509-SVID certificate. Any remaining certificates (if any) chain
     * the X.509-SVID certificate back to an X.509 root for the trust domain.
     */
    List<X509Certificate> chain;

    PrivateKey privateKey;

    private X509Svid(
            final SpiffeId spiffeId,
            final List<X509Certificate> chain,
            final PrivateKey privateKey) {
        this.spiffeId = spiffeId;
        this.chain = chain;
        this.privateKey = privateKey;
    }

    /**
     * @return the Leaf X.509 certificate of the chain
     */
    public X509Certificate getLeaf() {
        return chain.get(0);
    }

    /**
     * @return the chain of X.509 certificates
     */
    public List<X509Certificate> getChain() {
        return Collections.unmodifiableList(chain);
    }

    /**
     * Loads the X.509 SVID from PEM encoded files on disk.
     * <p>
     * It is assumed that the leaf certificate is always the first certificate in the parsed chain.
     *
     * @param certsFilePath      path to X.509 certificate chain file
     * @param privateKeyFilePath path to private key file
     * @return an instance of {@link X509Svid}
     * @throws X509SvidException if there is an error parsing the given certsFilePath or the privateKeyFilePath
     */
    public static X509Svid load(@NonNull final Path certsFilePath, @NonNull final Path privateKeyFilePath)
            throws X509SvidException {
        final byte[] certsBytes;
        try {
            certsBytes = Files.readAllBytes(certsFilePath);
        } catch (IOException e) {
            throw new X509SvidException("Cannot read certificate file", e);
        }

        final byte[] privateKeyBytes;
        try {
            privateKeyBytes = Files.readAllBytes(privateKeyFilePath);
        } catch (IOException e) {
            throw new X509SvidException("Cannot read private key file", e);
        }
        return createX509Svid(certsBytes, privateKeyBytes, KeyFileFormat.PEM);
    }

    /**
     * Parses the X.509 SVID from PEM or DER blocks containing certificate chain and key
     * bytes. The key must be a PEM block with PKCS#8.
     * <p>
     * It is assumed that the leaf certificate is always the first certificate in the parsed chain.
     *
     * @param certsBytes      chain of certificates as a byte array
     * @param privateKeyBytes private key as byte array
     * @return a {@link X509Svid} parsed from the given certBytes and privateKeyBytes
     * @throws X509SvidException if the given certsBytes or privateKeyBytes cannot be parsed
     */
    public static X509Svid parse(@NonNull final byte[] certsBytes, @NonNull final byte[] privateKeyBytes)
            throws X509SvidException {
        return createX509Svid(certsBytes, privateKeyBytes, KeyFileFormat.PEM);
    }

    /**
     * Parses the X509-SVID from certificate and key bytes. The certificate must be ASN.1 DER (concatenated with
     * no intermediate padding if there are more than one certificate). The key must be a PKCS#8 ASN.1 DER.
     * <p>
     * It is assumed that the leaf certificate is always the first certificate in the parsed chain.
     *
     * @param certsBytes      chain of certificates as a byte array
     * @param privateKeyBytes private key as byte array
     * @return a {@link X509Svid} parsed from the given certBytes and privateKeyBytes
     * @throws X509SvidException if the given certsBytes or privateKeyBytes cannot be parsed
     */
    public static X509Svid parseRaw(@NonNull final byte[] certsBytes,
                                    @NonNull final byte[] privateKeyBytes) throws X509SvidException {
        return createX509Svid(certsBytes, privateKeyBytes, KeyFileFormat.DER);
    }

    /**
     * @return the chain of certificates as an array of {@link X509Certificate}
     */
    public X509Certificate[] getChainArray() {
        return chain.toArray(new X509Certificate[0]);
    }

    private static X509Svid createX509Svid(final byte[] certsBytes,
                                           final byte[] privateKeyBytes,
                                           final KeyFileFormat keyFileFormat) throws X509SvidException {

        val x509Certificates = generateX509Certificates(certsBytes);
        val privateKey = generatePrivateKey(privateKeyBytes, keyFileFormat, x509Certificates);
        val spiffeId = getSpiffeId(x509Certificates);

        validatePrivateKey(privateKey, x509Certificates);
        validateLeafCertificate(x509Certificates.get(0));

        // there are intermediate CA certificates
        if (x509Certificates.size() > 1) {
            validateSigningCertificates(x509Certificates);
        }

        return new X509Svid(spiffeId, x509Certificates, privateKey);
    }

    private static SpiffeId getSpiffeId(final List<X509Certificate> x509Certificates) throws X509SvidException {
        final SpiffeId spiffeId;
        try {
            spiffeId = CertificateUtils.getSpiffeId(x509Certificates.get(0));
        } catch (CertificateException e) {
            throw new X509SvidException(e.getMessage(), e);
        }
        return spiffeId;
    }

    private static PrivateKey generatePrivateKey(final byte[] privateKeyBytes,
                                                 final KeyFileFormat keyFileFormat,
                                                 final List<X509Certificate> x509Certificates)
            throws X509SvidException {

        val publicKeyCertAlgorithm = x509Certificates.get(0).getPublicKey().getAlgorithm();
        val algorithm = AsymmetricKeyAlgorithm.parse(publicKeyCertAlgorithm);
        final PrivateKey privateKey;
        try {
            privateKey = CertificateUtils.generatePrivateKey(privateKeyBytes, algorithm, keyFileFormat);
        } catch (InvalidKeySpecException | InvalidKeyException | NoSuchAlgorithmException e) {
            throw new X509SvidException("Private Key could not be parsed from key bytes", e);
        }
        return privateKey;
    }

    private static List<X509Certificate> generateX509Certificates(final byte[] certsBytes) throws X509SvidException {
        final List<X509Certificate> x509Certificates;
        try {
            x509Certificates = CertificateUtils.generateCertificates(certsBytes);
        } catch (CertificateParsingException e) {
            throw new X509SvidException("Certificate could not be parsed from cert bytes", e);
        }
        return x509Certificates;
    }

    private static void validateSigningCertificates(final List<X509Certificate> certificates) throws X509SvidException {
        for (int i = 1; i < certificates.size(); i++) {
            verifyCaCert(certificates.get(i));
        }
    }

    private static void verifyCaCert(final X509Certificate cert) throws X509SvidException {
        if (!CertificateUtils.isCA(cert)) {
            throw new X509SvidException("Signing certificate must have CA flag set to true");
        }
        if (!CertificateUtils.hasKeyUsageCertSign(cert)) {
            throw new X509SvidException("Signing certificate must have 'keyCertSign' as key usage");
        }
    }

    private static void validateLeafCertificate(final X509Certificate leaf) throws X509SvidException {
        if (CertificateUtils.isCA(leaf)) {
            throw new X509SvidException("Leaf certificate must not have CA flag set to true");
        }
        validateKeyUsageOfLeafCertificate(leaf);
    }

    private static void validateKeyUsageOfLeafCertificate(final X509Certificate leaf) throws X509SvidException {
        if (!CertificateUtils.hasKeyUsageDigitalSignature(leaf)) {
            throw new X509SvidException("Leaf certificate must have 'digitalSignature' as key usage");
        }
        if (CertificateUtils.hasKeyUsageCertSign(leaf)) {
            throw new X509SvidException("Leaf certificate must not have 'keyCertSign' as key usage");
        }
        if (CertificateUtils.hasKeyUsageCRLSign(leaf)) {
            throw new X509SvidException("Leaf certificate must not have 'cRLSign' as key usage");
        }
    }

    private static void validatePrivateKey(final PrivateKey privateKey, final List<X509Certificate> x509Certificates)
            throws X509SvidException {
        try {
            CertificateUtils.validatePrivateKey(privateKey, x509Certificates.get(0));
        } catch (InvalidKeyException e) {
            throw new X509SvidException("Private Key does not match Certificate Public Key", e);
        }
    }
}
