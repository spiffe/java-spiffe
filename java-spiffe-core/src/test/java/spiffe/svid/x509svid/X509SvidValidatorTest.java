package spiffe.svid.x509svid;

import lombok.val;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import spiffe.bundle.x509bundle.X509Bundle;
import spiffe.bundle.x509bundle.X509BundleSource;
import spiffe.exception.BundleNotFoundException;
import spiffe.internal.CertificateUtils;
import spiffe.spiffeid.SpiffeId;
import spiffe.spiffeid.TrustDomain;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.when;

public class X509SvidValidatorTest {

    @Mock
    X509BundleSource bundleSourceMock;

    @BeforeEach
    void setup() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    void verifyChain_certificateExpired_throwsCertificateException() throws IOException, CertificateException, BundleNotFoundException, URISyntaxException {
        val certPath = Paths.get(loadResource("testdata/x509svid/cert.pem"));
        val certBytes = Files.readAllBytes(certPath);
        val chain = CertificateUtils.generateCertificates(certBytes);

        val bundlePath = Paths.get(loadResource("testdata/x509svid/bundle.pem"));
        X509Bundle x509Bundle=
                X509Bundle.load(
                        TrustDomain.of("example.org"),
                        bundlePath
                );

        when(bundleSourceMock
                .getX509BundleForTrustDomain(
                        TrustDomain.of("example.org")))
                .thenReturn(x509Bundle);

        try {
            X509SvidValidator.verifyChain(chain, bundleSourceMock);
            fail("Verify chain should have thrown validation exception");
        } catch (CertificateException e) {
            assertEquals("Cert chain cannot be verified", e.getMessage());
        }
    }

    @Test
    void verifyChain_noBundleForTrustDomain_throwsBundleNotFoundException() throws IOException, CertificateException, BundleNotFoundException, URISyntaxException {
        val certPath = Paths.get(loadResource("testdata/x509svid/cert.pem"));
        val certBytes = Files.readAllBytes(certPath);
        val chain = CertificateUtils.generateCertificates(certBytes);

        val bundlePath = Paths.get(loadResource("testdata/x509svid/bundle.pem"));
        X509Bundle x509Bundle=
                X509Bundle.load(
                        TrustDomain.of("example.org"),
                        bundlePath
                );

        when(bundleSourceMock
                .getX509BundleForTrustDomain(
                        TrustDomain.of("example.org")))
                .thenThrow(new BundleNotFoundException("No bundle found"));

        try {
            X509SvidValidator.verifyChain(chain, bundleSourceMock);
            fail("Verify chain should have thrown validation exception");
        } catch (BundleNotFoundException e) {
            assertEquals("No bundle found", e.getMessage());
        }
    }

    @Test
    void checkSpiffeId_givenASpiffeIdInTheListOfAcceptedIds_doesntThrowException() throws IOException, CertificateException, URISyntaxException {
        val spiffeId1 = SpiffeId.parse("spiffe://example.org/test");
        val spiffeId2 = SpiffeId.parse("spiffe://example.org/test2");

        val certPath = Paths.get(loadResource("testdata/x509svid/cert.pem"));
        val certBytes = Files.readAllBytes(certPath);
        val x509Certificate = CertificateUtils.generateCertificates(certBytes);

        val spiffeIdList = Arrays.asList(spiffeId1, spiffeId2);

        X509SvidValidator.verifySpiffeId(x509Certificate.get(0), () -> spiffeIdList);
    }

    @Test
    void checkSpiffeId_givenASpiffeIdNotInTheListOfAcceptedIds_throwsCertificateException() throws IOException, CertificateException, URISyntaxException {
        val spiffeId1 = SpiffeId.parse("spiffe://example.org/other1");
        val spiffeId2 = SpiffeId.parse("spiffe://example.org/other2");
        List<SpiffeId> spiffeIdList = Arrays.asList(spiffeId1, spiffeId2);

        val certPath = Paths.get(loadResource("testdata/x509svid/cert.pem"));
        val certBytes = Files.readAllBytes(certPath);
        val x509Certificate = CertificateUtils.generateCertificates(certBytes);

        try {
            X509SvidValidator.verifySpiffeId(x509Certificate.get(0), () -> spiffeIdList);
            fail("Should have thrown CertificateException");
        } catch (CertificateException e) {
            assertEquals("SPIFFE ID spiffe://example.org/test in X.509 certificate is not accepted", e.getMessage());
        }
    }

    private URI loadResource(String path) throws URISyntaxException {
        return getClass().getClassLoader().getResource(path).toURI();
    }
}
