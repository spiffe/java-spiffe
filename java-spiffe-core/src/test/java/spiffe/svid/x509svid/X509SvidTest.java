package spiffe.svid.x509svid;

import lombok.val;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

public class X509SvidTest {

    @Test
    void parse_GivenCertAndPrivateKeyPEMsInByteArrays_ReturnsX509Svid() throws IOException {
        val certPem = Files.readAllBytes(Paths.get("../testdata/x509cert.pem"));
        val keyPem = Files.readAllBytes(Paths.get("../testdata/pkcs8key.pem"));

        val result = X509Svid.parse(certPem, keyPem);

        assertAll("X509-SVID",
                () -> assertTrue(result.isOk()),
                () -> assertEquals("spiffe://example.org/test", result.getValue().getSpiffeId().toString()),
                () -> assertEquals(1, result.getValue().getChain().size()),
                () -> assertNotNull(result.getValue().getPrivateKey())
        );
    }

    @Test
    void parse_GivenChainOfCertsAndPrivateKeyPEMsInByteArrays_ReturnsX509Svid() throws IOException {
        val certPem = Files.readAllBytes(Paths.get("../testdata/x509chain.pem"));
        val keyPem = Files.readAllBytes(Paths.get("../testdata/pkcs8key.pem"));

        val result = X509Svid.parse(certPem, keyPem);

        assertAll("X509-SVID",
                () -> assertEquals("spiffe://example.org/test", result.getValue().getSpiffeId().toString()),
                () -> assertEquals(4, result.getValue().getChain().size()),
                () -> assertNotNull(result.getValue().getPrivateKey())
        );
    }

    @Test
    void load_GivenCertAndPrivateKeyPaths_ReturnsX509Svid() {
        val certsFile = Paths.get("../testdata/x509cert.pem");
        val privateKeyFile = Paths.get("../testdata/pkcs8key.pem");

        val result = X509Svid.load(certsFile, privateKeyFile);

        assertAll("X509-SVID",
                () -> assertEquals("spiffe://example.org/test", result.getValue().getSpiffeId().toString()),
                () -> assertEquals(1, result.getValue().getChain().size()),
                () -> assertNotNull(result.getValue().getPrivateKey())
        );
    }
}
