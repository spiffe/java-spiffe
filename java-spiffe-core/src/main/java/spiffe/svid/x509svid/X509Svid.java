package spiffe.svid.x509svid;

import lombok.NonNull;
import lombok.Value;
import lombok.val;
import spiffe.exception.X509SvidException;
import spiffe.internal.CertificateUtils;
import spiffe.spiffeid.SpiffeId;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

/**
 * A <code>X509Svid</code> represents a SPIFFE X.509 SVID.
 * <p>
 * Contains a SPIFFE ID, a private key and a chain of X.509 certificates.
 */
@Value
public class X509Svid {

    SpiffeId spiffeId;

    /**
     * The X.509 certificates of the X.509-SVID. The leaf certificate is
     * the X.509-SVID certificate. Any remaining certificates (if any) chain
     * the X.509-SVID certificate back to a X.509 root for the trust domain.
     */
    List<X509Certificate> chain;

    PrivateKey privateKey;

    private X509Svid(
            @NonNull SpiffeId spiffeId,
            @NonNull List<X509Certificate> chain,
            @NonNull PrivateKey privateKey) {
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
     *
     * @throws X509SvidException if there is an error parsing the given certsFilePath or the privateKeyFilePath
     */
    public static X509Svid load(@NonNull Path certsFilePath, @NonNull Path privateKeyFilePath) throws X509SvidException {
        byte[] certsBytes;
        byte[] privateKeyBytes;
        try {
            certsBytes = Files.readAllBytes(certsFilePath);
            privateKeyBytes = Files.readAllBytes(privateKeyFilePath);
        } catch (IOException e) {
            throw new X509SvidException(String.format("Could not load X509Svid from certsFilePath %s and privateKeyFilePath %s", certsFilePath, privateKeyFilePath), e);
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
     *
     * @throws X509SvidException if the given certsBytes or privateKeyBytes cannot be parsed
     */
    public static X509Svid parse(@NonNull byte[] certsBytes, @NonNull byte[] privateKeyBytes) throws X509SvidException {
        return createX509Svid(certsBytes, privateKeyBytes);
    }

    /**
     * Return the chain of certificates as an array.
     */
    public X509Certificate[] getChainArray() {
        return chain.toArray(new X509Certificate[0]);
    }

    private static X509Svid createX509Svid(byte[] certsBytes, byte[] privateKeyBytes) throws X509SvidException {
        List<X509Certificate> x509Certificates = null;
        try {
            x509Certificates = CertificateUtils.generateCertificates(certsBytes);
            val privateKey = CertificateUtils.generatePrivateKey(privateKeyBytes);
            val spiffeId = CertificateUtils.getSpiffeId(x509Certificates.get(0));
            return new X509Svid(spiffeId, x509Certificates, privateKey);
        } catch (CertificateException e) {
            throw new X509SvidException("X509 SVID could not be parsed from cert bytes", e);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new X509SvidException("X509 SVID Private Key could not be parsed from privateKeyBytes", e);
        }
    }
}
