package spiffe.internal;

import lombok.val;
import org.junit.jupiter.api.Test;
import spiffe.spiffeid.SpiffeId;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class CertificateUtilsTest {

    @Test
    void generateCertificates_ofPEMByteArray_returnsListWithOneX509Certificate() throws IOException {
        val certBytes = Files.readAllBytes(Paths.get("../testdata/x509cert.pem"));

        List<X509Certificate> x509CertificateList = null;
        SpiffeId spiffeId = null;
        try {
            x509CertificateList = CertificateUtils.generateCertificates(certBytes);
            spiffeId = CertificateUtils.getSpiffeId(x509CertificateList.get(0));
        } catch (CertificateException e) {
            fail("Not expected exception. Should have generated the certificates", e);
        }

        assertEquals("spiffe://example.org/test", spiffeId.toString());
    }

    @Test
    void validate_certificateThatIsExpired_throwsCertificateException() throws IOException, CertificateException {
        val certBytes = Files.readAllBytes(Paths.get("../testdata/x509cert_other.pem"));
        val bundleBytes = Files.readAllBytes(Paths.get("../testdata/bundle_other.pem"));

        val chain = CertificateUtils.generateCertificates(certBytes);
        val trustedCert = CertificateUtils.generateCertificates(bundleBytes);

        try {
            CertificateUtils.validate(chain, trustedCert);
            fail("Expected exception");
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | CertPathValidatorException e) {
            assertEquals("validity check failed", e.getMessage());
        }
    }
}
