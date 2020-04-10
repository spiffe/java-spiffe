package spiffe.bundle.x509bundle;

import org.junit.jupiter.api.Test;
import spiffe.result.Result;
import spiffe.spiffeid.TrustDomain;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class X509BundleTest {

    @Test
    void parse_bundleByteArrayInPEMFormatAndTrustDomain_returnX509Bundle() throws IOException {
        byte[] bundlePem = Files.readAllBytes(Paths.get("../testdata/bundle.pem"));
        TrustDomain trustDomain = TrustDomain.of("example.org").getValue();

        Result<X509Bundle, Throwable> x509Bundle = X509Bundle.parse(trustDomain, bundlePem);

        assertAll(
                () -> assertEquals(2, x509Bundle.getValue().getX509Roots().size()),
                () -> assertEquals("example.org", x509Bundle.getValue().getTrustDomain().toString())
        );
    }

    @Test
    void load_bundleByteArrayInPEMFormatAndTrustDomain_returnX509Bundle() {
        Path bundlePath = Paths.get("../testdata/bundle.pem");
        TrustDomain trustDomain = TrustDomain.of("example.org").getValue();

        Result<X509Bundle, Throwable> x509Bundle = X509Bundle.load(trustDomain, bundlePath);

        assertAll(
                () -> assertEquals(2, x509Bundle.getValue().getX509Roots().size()),
                () -> assertEquals("example.org", x509Bundle.getValue().getTrustDomain().toString())
        );
    }
}
