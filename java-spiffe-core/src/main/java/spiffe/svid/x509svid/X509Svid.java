package spiffe.svid.x509svid;

import lombok.NonNull;
import lombok.Value;
import lombok.val;
import spiffe.internal.CertificateUtils;
import spiffe.result.Result;
import spiffe.spiffeid.SpiffeId;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * A <code>X509Svid</code> represents a SPIFFE X509-SVID.
 * <p>
 * Contains a SPIFFE ID, a PrivateKey and a chain of X509Certificate.
 */
@Value
public class X509Svid {

    SpiffeId spiffeId;

    // The X.509 certificates of the X509-SVID. The leaf certificate is
    // the X509-SVID certificate. Any remaining certificates (if any)
    // chain the X509-SVID certificate back to a X509 root
    // for the trust domain.
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
     * Loads the X509-SVID from PEM encoded files on disk.
     *
     * @param certsFile      path to x509 certificate chain file
     * @param privateKeyFile path to PrivateKey file
     * @return an instance of X509Svid
     */
    public static Result<X509Svid, String> load(@NonNull Path certsFile, @NonNull Path privateKeyFile) {
        try {
            val certsBytes = Files.readAllBytes(certsFile);
            byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile);
            return createX509Svid(certsBytes, privateKeyBytes);
        } catch (IOException e) {
            return Result.error("Error loading X509-SVID from certsFile %s and privateKeyFile %s: %s", certsFile, privateKeyFile, e.getMessage());
        }
    }

    /**
     * Parses the X509-SVID from PEM or DER blocks containing certificate chain and key
     * bytes. The key must be a PEM or DER block with PKCS#8.
     *
     * @param certsBytes      chain of certificates as a byte array
     * @param privateKeyBytes private key byte array
     * @return a Result(Success) object containing the X509-SVID, or a Error containing the Exception cause
     */
    public static Result<X509Svid, String> parse(@NonNull byte[] certsBytes, @NonNull byte[] privateKeyBytes) {
        return createX509Svid(certsBytes, privateKeyBytes);
    }

    /** Return the chain of certificates as an array. */
    public X509Certificate[] getChainArray() {
        return chain.toArray(new X509Certificate[0]);
    }

    private static Result<X509Svid, String> createX509Svid(byte[] certsBytes, byte[] privateKeyBytes) {
        val x509Certificates = CertificateUtils.generateCertificates(certsBytes);
        if (x509Certificates.isError()) {
            return Result.error(x509Certificates.getError());
        }

        val privateKey = CertificateUtils.generatePrivateKey(privateKeyBytes);
        if (privateKey.isError()) {
            return Result.error(privateKey.getError());
        }

        val spiffeId =
                CertificateUtils
                        .getSpiffeId(x509Certificates.getValue().get(0));
        if (spiffeId.isError()) {
            return Result.error("Error creating X509-SVID: %s", spiffeId.getError());
        }

        val x509Svid = new X509Svid(
                spiffeId.getValue(),
                x509Certificates.getValue(),
                privateKey.getValue());

        return Result.ok(x509Svid);
    }

}
