package spiffe.internal;

import lombok.val;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CertificateUtilsTest {

    @Test
    void generateCertificates_ofPEMByteArray_returnsListWithOneX509Certificate() throws IOException {
        val certBytes = Files.readAllBytes(Paths.get("../testdata/x509cert.pem"));

        val x509CertificateList = CertificateUtils.generateCertificates(certBytes);

        val spiffeId = CertificateUtils.getSpiffeId(x509CertificateList.getValue().get(0));
        assertEquals("spiffe://example.org/test", spiffeId.getValue().toString());
    }

    @Test
    void validate_certificateThatIsExpired_ReturnsError() throws IOException {
        val certBytes = Files.readAllBytes(Paths.get("../testdata/x509cert_other.pem"));
        val bundleBytes = Files.readAllBytes(Paths.get("../testdata/bundle_other.pem"));

        val chain = CertificateUtils.generateCertificates(certBytes);
        val trustedCert = CertificateUtils.generateCertificates(bundleBytes);

        val result = CertificateUtils.validate(chain.getValue(), trustedCert.getValue());

        assertTrue(result.isError());
        assertTrue(result.getError().contains("Error validating certificate chain: validity check failed"));
    }
}
