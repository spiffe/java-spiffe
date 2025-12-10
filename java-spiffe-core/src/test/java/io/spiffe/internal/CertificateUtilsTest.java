package io.spiffe.internal;

import com.nimbusds.jose.jwk.Curve;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.utils.CertAndKeyPair;
import io.spiffe.utils.TestUtils;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static io.spiffe.internal.AsymmetricKeyAlgorithm.RSA;
import static io.spiffe.utils.TestUtils.toUri;
import static io.spiffe.utils.X509CertificateTestUtils.createCertificate;
import static io.spiffe.utils.X509CertificateTestUtils.createRootCA;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

public class CertificateUtilsTest {

    @Test
    void generateCertificates_ofPEMByteArray_returnsListWithOneX509Certificate() throws IOException, URISyntaxException {
        final Path path = Paths.get(toUri("testdata/internal/cert.pem"));
        final byte[] certBytes = Files.readAllBytes(path);

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
        final Path certPath = Paths.get(toUri("testdata/internal/cert2.pem"));
        final Path certBundle = Paths.get(toUri("testdata/internal/bundle.pem"));

        final byte[] certBytes = Files.readAllBytes(certPath);
        final byte[] bundleBytes = Files.readAllBytes(certBundle);

        final List<X509Certificate> chain = CertificateUtils.generateCertificates(certBytes);
        List<X509Certificate> trustedCert;
        trustedCert = CertificateUtils.generateCertificates(bundleBytes);

        try {
            CertificateUtils.validate(chain, trustedCert);
            fail("Expected exception");
        } catch (CertPathValidatorException e) {
            assertEquals("validity check failed", e.getMessage());
        }
    }

    @Test
    void validateCerts_nullTrustedCerts() throws URISyntaxException, IOException, CertificateParsingException {
        final Path certPath = Paths.get(toUri("testdata/internal/cert2.pem"));
        final byte[] certBytes = Files.readAllBytes(certPath);
        final List<X509Certificate> chain = CertificateUtils.generateCertificates(certBytes);

        try {
            CertificateUtils.validate(chain, null);
        } catch (CertificateException e) {
            assertEquals("No trusted Certs", e.getMessage());
        } catch (CertPathValidatorException e) {
            fail(e);
        }
    }

    @Test
    void validateCerts_emptyTrustedCerts() throws URISyntaxException, IOException, CertificateParsingException {
        final Path certPath = Paths.get(toUri("testdata/internal/cert2.pem"));
        final byte[] certBytes = Files.readAllBytes(certPath);
        final List<X509Certificate> chain = CertificateUtils.generateCertificates(certBytes);

        try {
            CertificateUtils.validate(chain, Collections.emptyList());
        } catch (CertificateException e) {
            assertEquals("No trusted Certs", e.getMessage());
        } catch (CertPathValidatorException e) {
            fail(e);
        }
    }

    @Test
    void validateCerts_nullChain() throws URISyntaxException, IOException, CertificateParsingException {
        final Path certPath = Paths.get(toUri("testdata/internal/cert2.pem"));
        final byte[] certBytes = Files.readAllBytes(certPath);
        final List<X509Certificate> certificates = CertificateUtils.generateCertificates(certBytes);

        try {
            CertificateUtils.validate(null, certificates);
        } catch (CertificateException | CertPathValidatorException e) {
            fail(e);
        } catch (IllegalArgumentException e) {
            assertEquals("Chain of certificates is empty", e.getMessage());
        }
    }

    @Test
    void validateCerts_emptyChain() throws URISyntaxException, IOException, CertificateParsingException {
        final Path certPath = Paths.get(toUri("testdata/internal/cert2.pem"));
        final byte[] certBytes = Files.readAllBytes(certPath);
        final List<X509Certificate> certificates = CertificateUtils.generateCertificates(certBytes);

        try {
            CertificateUtils.validate(Collections.emptyList(), certificates);
        } catch (CertificateException | CertPathValidatorException e) {
            fail(e);
        } catch (IllegalArgumentException e) {
            assertEquals("Chain of certificates is empty", e.getMessage());
        }
    }

    @Test
    void testGenerateRsaPrivateKeyFromBytes() throws URISyntaxException, IOException {
        final Path keyPath = Paths.get(toUri("testdata/internal/privateKeyRsa.pem"));
        final byte[] keyBytes = Files.readAllBytes(keyPath);

        try {
            PrivateKey privateKey = CertificateUtils.generatePrivateKey(keyBytes, RSA, KeyFileFormat.PEM);
            assertNotNull(privateKey);
            assertEquals(RSA.value(), privateKey.getAlgorithm());
        } catch (InvalidKeySpecException | InvalidKeyException | NoSuchAlgorithmException e) {
            fail("Should have generated key", e);
        }
    }

    @Test
    void testGenerateEcPrivateKeyFromBytes() {
        KeyPair ecKeyPair = TestUtils.generateECKeyPair(Curve.P_256);
        byte[] keyBytes = ecKeyPair.getPrivate().getEncoded();

        try {
            PrivateKey privateKey = CertificateUtils.generatePrivateKey(keyBytes, AsymmetricKeyAlgorithm.EC, KeyFileFormat.DER);
            assertNotNull(privateKey);
            assertEquals("EC", privateKey.getAlgorithm());
        } catch (InvalidKeySpecException | InvalidKeyException | NoSuchAlgorithmException e) {
            fail("Should have generated key", e);
        }
    }

    @Test
    void testGetSpiffeId() throws Exception {
        final CertAndKeyPair rootCa = createRootCA("C = US, O = SPIFFE", "spiffe://domain.test");
        final CertAndKeyPair leaf = createCertificate("C = US, O = SPIRE", "C = US, O = SPIRE", "spiffe://domain.test/workload", rootCa, false);
        SpiffeId spiffeId = CertificateUtils.getSpiffeId(leaf.getCertificate());
        assertEquals(SpiffeId.parse("spiffe://domain.test/workload"), spiffeId);
    }

    @Test
    void testGetSpiffeId_certNotContainSpiffeId_throwsCertificateException() throws Exception {
        final CertAndKeyPair rootCa = createRootCA("C = US, O = SPIFFE", "spiffe://domain.test");
        final CertAndKeyPair leaf = createCertificate("C = US, O = SPIRE", "C = US, O = SPIRE", "", rootCa, false);
        try {
            CertificateUtils.getSpiffeId(leaf.getCertificate());
            fail("exception is expected");
        } catch (CertificateException e) {
            assertEquals("Certificate does not contain SPIFFE ID in the URI SAN", e.getMessage());
        }
    }

    @Test
    void testGetTrustDomain() throws Exception {
        final CertAndKeyPair rootCa = createRootCA("C = US, O = SPIFFE", "spiffe://domain.test");
        final CertAndKeyPair intermediate = createCertificate("C = US, O = SPIRE", "C = US, O = SPIRE", "spiffe://domain.test/host", rootCa, true);
        final CertAndKeyPair leaf = createCertificate("C = US, O = SPIRE", "C = US, O = SPIRE", "spiffe://domain.test/workload", intermediate, false);

        final List<X509Certificate> chain = Arrays.asList(leaf.getCertificate(), intermediate.getCertificate());

        try {
            TrustDomain trustDomain = CertificateUtils.getTrustDomain(chain);
            assertNotNull(trustDomain);
            assertEquals(TrustDomain.parse("domain.test"), trustDomain);
        } catch (CertificateException e) {
            fail(e);
        }
    }
}
