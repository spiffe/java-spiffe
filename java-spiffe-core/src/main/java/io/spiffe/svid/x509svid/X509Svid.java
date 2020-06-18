package io.spiffe.svid.x509svid;

import io.spiffe.exception.X509SvidException;
import io.spiffe.internal.CertificateUtils;
import io.spiffe.spiffeid.SpiffeId;
import lombok.NonNull;
import lombok.Value;

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
import java.util.List;

/**
 * Represents a SPIFFE X.509 SVID.
 * <p>
 * Contains a SPIFFE ID, a private key and a chain of X.509 certificates.
 */
@Value
public class X509Svid implements X509SvidSource {

    SpiffeId spiffeId;

    /**
     * The X.509 certificates of the X.509-SVID. The leaf certificate is
     * the X.509-SVID certificate. Any remaining certificates (if any) chain
     * the X.509-SVID certificate back to an X.509 root for the trust domain.
     */
    List<X509Certificate> chain;

    PrivateKey privateKey;

    private X509Svid(
            SpiffeId spiffeId,
            List<X509Certificate> chain,
            PrivateKey privateKey) {
        this.spiffeId = spiffeId;
        this.chain = chain;
        this.privateKey = privateKey;
    }

    /**
     * Loads the X.509 SVID from PEM encoded files on disk.
     *
     * @param certsFilePath      path to X.509 certificate chain file
     * @param privateKeyFilePath path to private key file
     * @return an instance of {@link X509Svid}
     * @throws X509SvidException if there is an error parsing the given certsFilePath or the privateKeyFilePath
     */
    public static X509Svid load(@NonNull Path certsFilePath, @NonNull Path privateKeyFilePath) throws X509SvidException {
        byte[] certsBytes;
        byte[] privateKeyBytes;

        try {
            certsBytes = Files.readAllBytes(certsFilePath);
        } catch (IOException e) {
            throw new X509SvidException("Cannot read certificate file", e);
        }

        try {
            privateKeyBytes = Files.readAllBytes(privateKeyFilePath);
        } catch (IOException e) {
            throw new X509SvidException("Cannot read private key file", e);
        }
        return createX509Svid(certsBytes, privateKeyBytes);
    }

    /**
     * Parses the X.509 SVID from PEM or DER blocks containing certificate chain and key
     * bytes. The key must be a PEM or DER block with PKCS#8.
     *
     * @param certsBytes      chain of certificates as a byte array
     * @param privateKeyBytes private key as byte array
     * @return a {@link X509Svid} parsed from the given certBytes and privateKeyBytes
     * @throws X509SvidException if the given certsBytes or privateKeyBytes cannot be parsed
     */
    public static X509Svid parse(@NonNull byte[] certsBytes, @NonNull byte[] privateKeyBytes) throws X509SvidException {
        return createX509Svid(certsBytes, privateKeyBytes);
    }

    /**
     * @return the chain of certificates as an array of {@link X509Certificate}
     */
    public X509Certificate[] getChainArray() {
        return chain.toArray(new X509Certificate[0]);
    }

    private static X509Svid createX509Svid(byte[] certsBytes, byte[] privateKeyBytes) throws X509SvidException {
        List<X509Certificate> x509Certificates;
        PrivateKey privateKey;
        SpiffeId spiffeId;

        try {
            x509Certificates = CertificateUtils.generateCertificates(certsBytes);
        } catch (CertificateParsingException e) {
            throw new X509SvidException("Certificate could not be parsed from cert bytes", e);
        }

        try {
            privateKey = CertificateUtils.generatePrivateKey(privateKeyBytes);
        } catch (InvalidKeySpecException | InvalidKeyException | NoSuchAlgorithmException e) {
            throw new X509SvidException("Private Key could not be parsed from key bytes", e);
        }

        try {
            spiffeId = CertificateUtils.getSpiffeId(x509Certificates.get(0));
        } catch (CertificateException e) {
            throw new X509SvidException(e.getMessage(), e);
        }

        validatePrivateKey(privateKey, x509Certificates);
        validateLeafCertificate(x509Certificates.get(0));

        if (x509Certificates.size() > 1) {
            validateSigningCertificates(x509Certificates.subList(1, x509Certificates.size()));
        }

        return new X509Svid(spiffeId, x509Certificates, privateKey);
    }

    private static void validateSigningCertificates(List<X509Certificate> certificates) throws X509SvidException {
        for (X509Certificate cert : certificates) {
            if (!CertificateUtils.isCA(cert)) {
                throw new X509SvidException("Signing certificate must have CA flag set to true");
            }
            if (!CertificateUtils.hasKeyUsageCertSign(cert)) {
                throw new X509SvidException("Signing certificate must have 'keyCertSign' as key usage");
            }
        }
    }

    private static void validateLeafCertificate(X509Certificate leaf) throws X509SvidException {
        if (CertificateUtils.isCA(leaf)) {
            throw new X509SvidException("Leaf certificate must not have CA flag set to true");
        }
        validateKeyUsage(leaf);
    }

    private static void validateKeyUsage(X509Certificate leaf) throws X509SvidException {
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

    private static void validatePrivateKey(PrivateKey privateKey, List<X509Certificate> x509Certificates) throws X509SvidException {
        try {
            CertificateUtils.validatePrivateKey(privateKey, x509Certificates.get(0));
        } catch (InvalidKeyException e) {
            throw new X509SvidException("Private Key does not match Certificate Public Key", e);
        }
    }

    @Override
    public X509Svid getX509Svid() {
        return this;
    }
}
