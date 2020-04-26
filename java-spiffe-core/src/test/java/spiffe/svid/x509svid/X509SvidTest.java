package spiffe.svid.x509svid;

import lombok.val;
import org.junit.jupiter.api.Test;
import spiffe.exception.X509SvidException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

public class X509SvidTest {

    @Test
    void parse_GivenCertAndPrivateKeyPEMsInByteArrays_ReturnsX509Svid() throws X509SvidException, IOException {
        val certPem = Files.readAllBytes(Paths.get("../testdata/x509cert.pem"));
        val keyPem = Files.readAllBytes(Paths.get("../testdata/pkcs8key.pem"));

        val x509Svid = X509Svid.parse(certPem, keyPem);

        assertAll("X509-SVID",
                () -> assertEquals("spiffe://example.org/test", x509Svid.getSpiffeId().toString()),
                () -> assertEquals(1, x509Svid.getChain().size()),
                () -> assertNotNull(x509Svid.getPrivateKey())
        );
    }

    @Test
    void parse_GivenChainOfCertsAndPrivateKeyPEMsInByteArrays_ReturnsX509Svid() throws IOException, X509SvidException {
        val certPem = Files.readAllBytes(Paths.get("../testdata/x509chain.pem"));
        val keyPem = Files.readAllBytes(Paths.get("../testdata/pkcs8key.pem"));

        val result = X509Svid.parse(certPem, keyPem);

        assertAll("X509-SVID",
                () -> assertEquals("spiffe://example.org/test", result.getSpiffeId().toString()),
                () -> assertEquals(4, result.getChain().size()),
                () -> assertNotNull(result.getPrivateKey())
        );
    }

    @Test
    void load_GivenCertAndPrivateKeyPaths_ReturnsX509Svid() throws X509SvidException {
        val certsFile = Paths.get("../testdata/x509cert.pem");
        val privateKeyFile = Paths.get("../testdata/pkcs8key.pem");

        X509Svid result;
        try {
            result = X509Svid.load(certsFile, privateKeyFile);
        } catch (X509SvidException e) {
            fail("Not expected exception", e);
            throw e;
        }

        assertAll("X509-SVID",
                () -> assertEquals("spiffe://example.org/test", result.getSpiffeId().toString()),
                () -> assertEquals(1, result.getChain().size()),
                () -> assertNotNull(result.getPrivateKey())
        );
    }
}
