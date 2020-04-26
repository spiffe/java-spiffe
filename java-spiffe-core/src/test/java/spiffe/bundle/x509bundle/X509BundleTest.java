package spiffe.bundle.x509bundle;

import org.junit.jupiter.api.Test;
import spiffe.spiffeid.TrustDomain;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class X509BundleTest {

    @Test
    void parse_bundleByteArrayInPEMFormatAndTrustDomain_returnX509Bundle() throws IOException {
        byte[] bundlePem = Files.readAllBytes(Paths.get("../testdata/bundle.pem"));
        TrustDomain trustDomain = TrustDomain.of("example.org");

        X509Bundle x509Bundle = null;
        try {
            x509Bundle = X509Bundle.parse(trustDomain, bundlePem);
        } catch (CertificateException e) {
            fail("Not expected exception", e);
        }

        assertEquals(1, x509Bundle.getX509Authorities().size());
        assertEquals("example.org", x509Bundle.getTrustDomain().toString());
    }

    @Test
    void load_bundleByteArrayInPEMFormatAndTrustDomain_returnX509Bundle() {
        Path bundlePath = Paths.get("../testdata/bundle.pem");
        TrustDomain trustDomain = TrustDomain.of("example.org");

        X509Bundle x509Bundle = null;
        try {
            x509Bundle = X509Bundle.load(trustDomain, bundlePath);
        } catch (IOException | CertificateException e) {
            fail("Not expected exception", e);
        }

        assertEquals(1, x509Bundle.getX509Authorities().size());
        assertEquals("example.org", x509Bundle.getTrustDomain().toString());
    }
}
