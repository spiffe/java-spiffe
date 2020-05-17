package spiffe.provider;

import lombok.val;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import spiffe.bundle.x509bundle.X509Bundle;
import spiffe.bundle.x509bundle.X509BundleSource;
import spiffe.exception.BundleNotFoundException;
import spiffe.exception.X509SvidException;
import spiffe.spiffeid.SpiffeId;
import spiffe.spiffeid.TrustDomain;
import spiffe.svid.x509svid.X509Svid;

import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

public class SpiffeTrustManagerTest {

    @Mock
    X509BundleSource bundleSource;

    static X509Bundle x509Bundle;
    static X509Svid x509Svid;
    static X509Svid otherX509Svid;
    List<SpiffeId> acceptedSpiffeIds;
    X509TrustManager trustManager;

    @BeforeAll
    static void setupClass() throws IOException, CertificateException, X509SvidException, URISyntaxException {
        x509Svid = X509Svid
                .load(
                        Paths.get(loadResource("testdata/cert.pem")),
                        Paths.get(loadResource("testdata/key.pem")));
        otherX509Svid = X509Svid
                .load(
                        Paths.get(loadResource("testdata/cert2.pem")),
                        Paths.get(loadResource("testdata/key2.pem")));
        x509Bundle = X509Bundle
                .load(
                        TrustDomain.of("example.org"),
                        Paths.get(loadResource("testdata/bundle.pem")));
    }

    @BeforeEach
    void setupMocks() {
        MockitoAnnotations.initMocks(this);
        trustManager = (X509TrustManager)
                new SpiffeTrustManagerFactory()
                        .engineGetTrustManagers(
                                bundleSource,
                                () -> acceptedSpiffeIds)[0];
    }

    @Test
    void checkClientTrusted_passAExpiredCertificate_throwsException() throws BundleNotFoundException {
        acceptedSpiffeIds =
                Collections
                        .singletonList(
                                SpiffeId.parse("spiffe://example.org/test")
                        );

        val chain = x509Svid.getChainArray();

        when(bundleSource.getX509BundleForTrustDomain(TrustDomain.of("example.org"))).thenReturn(x509Bundle);

        try {
            trustManager.checkClientTrusted(chain, "");
            fail("CertificateException was expected");
        } catch (CertificateException e) {
            assertEquals("java.security.cert.CertPathValidatorException: validity check failed", e.getMessage());
        }
    }

    @Test
    void checkClientTrusted_passCertificateWithNonAcceptedSpiffeId_ThrowCertificateException() throws BundleNotFoundException {
        acceptedSpiffeIds =
                Collections
                        .singletonList(
                                SpiffeId.parse("spiffe://example.org/other")
                        );

        X509Certificate[] chain = x509Svid.getChainArray();

        when(bundleSource.getX509BundleForTrustDomain(TrustDomain.of("example.org")))
                .thenReturn(x509Bundle);

        try {
            trustManager.checkClientTrusted(chain, "");
            fail("CertificateException was expected");
        } catch (CertificateException e) {
            assertEquals("SPIFFE ID spiffe://example.org/test in X.509 certificate is not accepted", e.getMessage());
        }
    }

    @Test
    void checkClientTrusted_passCertificateThatDoesntChainToBundle_ThrowCertificateException() throws BundleNotFoundException {
        acceptedSpiffeIds =
                Collections
                        .singletonList(
                                SpiffeId.parse("spiffe://other.org/test")
                        );

        val chain = otherX509Svid.getChainArray();

        when(bundleSource.getX509BundleForTrustDomain(TrustDomain.of("other.org"))).thenReturn(x509Bundle);

        try {
            trustManager.checkClientTrusted(chain, "");
            fail("CertificateException was expected");
        } catch (CertificateException e) {
            assertTrue(e.getMessage().contains("CertPathValidatorException: Path does not chain with any of the trust anchors"));
        }
    }

    @Test
    void checkServerTrusted_passAnExpiredCertificate_ThrowsException() throws BundleNotFoundException {
        acceptedSpiffeIds =
                Collections
                        .singletonList(
                                SpiffeId.parse("spiffe://example.org/test")
                        );

        val chain = x509Svid.getChainArray();

        when(bundleSource.getX509BundleForTrustDomain(TrustDomain.of("example.org"))).thenReturn(x509Bundle);

        try {
            trustManager.checkServerTrusted(chain, "");
            fail("CertificateException was expected");
        } catch (CertificateException e) {
            assertEquals("java.security.cert.CertPathValidatorException: validity check failed", e.getMessage());
        }
    }

    @Test
    void checkServerTrusted_passCertificateWithNonAcceptedSpiffeId_ThrowCertificateException() throws BundleNotFoundException {
        acceptedSpiffeIds =
                Collections
                        .singletonList(
                                SpiffeId.parse("spiffe://example.org/other")
                        );

        val chain = x509Svid.getChainArray();

        when(bundleSource.getX509BundleForTrustDomain(TrustDomain.of("example.org"))).thenReturn(x509Bundle);

        try {
            trustManager.checkServerTrusted(chain, "");
            fail("CertificateException was expected");
        } catch (CertificateException e) {
            assertEquals("SPIFFE ID spiffe://example.org/test in X.509 certificate is not accepted", e.getMessage());
        }
    }

    @Test
    void checkServerTrusted_passCertificateThatDoesntChainToBundle_ThrowCertificateException() throws BundleNotFoundException {
        acceptedSpiffeIds =
                Collections
                        .singletonList(
                                SpiffeId.parse("spiffe://other.org/test")
                        );

        val chain = otherX509Svid.getChainArray();

        when(bundleSource.getX509BundleForTrustDomain(TrustDomain.of("other.org"))).thenReturn(x509Bundle);

        try {
            trustManager.checkServerTrusted(chain, "");
            fail("CertificateException was expected");
        } catch (CertificateException e) {
            assertTrue(e.getMessage().contains("CertPathValidatorException: Path does not chain with any of the trust anchors"));
        }
    }

    private static URI loadResource(String path) throws URISyntaxException {
        return SpiffeTrustManagerTest.class.getClassLoader().getResource(path).toURI();
    }
}
