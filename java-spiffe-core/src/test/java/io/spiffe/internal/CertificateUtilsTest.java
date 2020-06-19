package io.spiffe.internal;

import com.nimbusds.jose.jwk.Curve;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import lombok.val;
import org.junit.jupiter.api.Test;
import io.spiffe.utils.TestUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static io.spiffe.utils.X509CertificateTestUtils.createCertificate;
import static io.spiffe.utils.X509CertificateTestUtils.createRootCA;

public class CertificateUtilsTest {

    @Test
    void generateCertificates_ofPEMByteArray_returnsListWithOneX509Certificate() throws IOException, URISyntaxException {
        val path = Paths.get(toUri("testdata/internal/cert.pem"));
        val certBytes = Files.readAllBytes(path);

        List<X509Certificate> x509CertificateList;
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

    @Test
    void testGenerateiRsaPrivateKeyFromBytes() throws URISyntaxException, IOException {
        val keyPath = Paths.get(toUri("testdata/internal/privateKeyRsa.pem"));
        val keyBytes = Files.readAllBytes(keyPath);

        try {
            PrivateKey privateKey = CertificateUtils.generatePrivateKey(keyBytes);
            assertNotNull(privateKey);
            assertEquals("RSA", privateKey.getAlgorithm());
        } catch (InvalidKeySpecException | InvalidKeyException | NoSuchAlgorithmException e) {
            fail("Should have generated key", e);
        }
    }

    @Test
    void testGenerateEcPrivateKeyFromBytes() {
        KeyPair ecKeyPair = TestUtils.generateECKeyPair(Curve.P_256);
        byte[] keyBytes = ecKeyPair.getPrivate().getEncoded();

        try {
            PrivateKey privateKey = CertificateUtils.generatePrivateKey(keyBytes);
            assertNotNull(privateKey);
            assertEquals("EC", privateKey.getAlgorithm());
        } catch (InvalidKeySpecException | InvalidKeyException | NoSuchAlgorithmException e) {
            fail("Should have generated key", e);
        }
    }

    @Test
    void testGetSpiffeId() throws Exception {
        val rootCa = createRootCA("C = US, O = SPIFFE", "spiffe://domain.test" );
        val leaf = createCertificate("C = US, O = SPIRE", "C = US, O = SPIRE",  "spiffe://domain.test/workload", rootCa, false);
        SpiffeId spiffeId = CertificateUtils.getSpiffeId(leaf.getCertificate());
        assertEquals(SpiffeId.parse("spiffe://domain.test/workload"), spiffeId);
    }

    @Test
    void testGetSpiffeId_certNotContainSpiffeId_throwsCertificateException() throws Exception {
        val rootCa = createRootCA("C = US, O = SPIFFE", "spiffe://domain.test" );
        val leaf = createCertificate("C = US, O = SPIRE", "C = US, O = SPIRE",  "", rootCa, false);
        try {
            CertificateUtils.getSpiffeId(leaf.getCertificate());
            fail("exception is expected");
        } catch (CertificateException e) {
            assertEquals("Certificate does not contain SPIFFE ID in the URI SAN", e.getMessage());
        }
    }

    @Test
    void testGetTrustDomain() throws Exception {
        val rootCa = createRootCA("C = US, O = SPIFFE", "spiffe://domain.test" );
        val intermediate = createCertificate("C = US, O = SPIRE", "C = US, O = SPIRE",  "spiffe://domain.test/host", rootCa, true);
        val leaf = createCertificate("C = US, O = SPIRE", "C = US, O = SPIRE",  "spiffe://domain.test/workload", intermediate, false);

        val chain = Arrays.asList(leaf.getCertificate(), intermediate.getCertificate());

        try {
            TrustDomain trustDomain = CertificateUtils.getTrustDomain(chain);
            assertNotNull(trustDomain);
            assertEquals(TrustDomain.of("domain.test"), trustDomain);
        } catch (CertificateException e) {
            fail(e);
        }
    }

    private URI toUri(String path) throws URISyntaxException {
        return Thread.currentThread().getContextClassLoader().getResource(path).toURI();
    }

}
