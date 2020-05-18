package spiffe.internal;

import lombok.val;
import org.junit.jupiter.api.Test;
import spiffe.spiffeid.SpiffeId;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class CertificateUtilsTest {

    @Test
    void generateCertificates_ofPEMByteArray_returnsListWithOneX509Certificate() throws IOException, URISyntaxException {
        val path = Paths.get(toUri("testdata/internal/cert.pem"));
        val certBytes = Files.readAllBytes(path);

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
    void validate_certificateThatIsExpired_throwsCertificateException() throws IOException, CertificateException, URISyntaxException {
        val certPath = Paths.get(toUri("testdata/internal/cert2.pem"));
        val certBundle = Paths.get(toUri("testdata/internal/bundle.pem"));

        val certBytes = Files.readAllBytes(certPath);
        val bundleBytes = Files.readAllBytes(certBundle);

        val chain = CertificateUtils.generateCertificates(certBytes);
        val trustedCert = CertificateUtils.generateCertificates(bundleBytes);

        try {
            CertificateUtils.validate(chain, trustedCert);
            fail("Expected exception");
        } catch (CertPathValidatorException e) {
            assertEquals("validity check failed", e.getMessage());
        }
    }

    private URI toUri(String path) throws URISyntaxException {
        return getClass().getClassLoader().getResource(path).toURI();
    }
}
