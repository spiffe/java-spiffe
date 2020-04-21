package spiffe.provider;

import lombok.val;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import spiffe.bundle.x509bundle.X509Bundle;
import spiffe.bundle.x509bundle.X509BundleSource;
import spiffe.result.Result;
import spiffe.spiffeid.SpiffeId;
import spiffe.spiffeid.TrustDomain;
import spiffe.svid.x509svid.X509Svid;

import javax.net.ssl.X509TrustManager;
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
    static void setupClass() {
        x509Svid = X509Svid
                .load(
                        Paths.get("../testdata/x509cert.pem"),
                        Paths.get("../testdata/pkcs8key.pem"))
                .getValue();
        otherX509Svid = X509Svid
                .load(
                        Paths.get("../testdata/x509cert_other.pem"),
                        Paths.get("../testdata/key_other.pem"))
                .getValue();
        x509Bundle = X509Bundle
                .load(
                        TrustDomain.of("example.org").getValue(),
                        Paths.get("../testdata/bundle.pem"))
                .getValue();
    }

    @BeforeEach
    void setupMocks() {
        MockitoAnnotations.initMocks(this);
        trustManager = (X509TrustManager)
                new SpiffeTrustManagerFactory()
                        .engineGetTrustManagers(
                                bundleSource,
                                () -> Result.ok(acceptedSpiffeIds))[0];
    }

    @Test
    void checkClientTrusted_passAExpiredCertificate_throwsException() {
        acceptedSpiffeIds =
                Collections
                        .singletonList(
                                SpiffeId.parse("spiffe://example.org/test").getValue()
                        );

        val chain = x509Svid.getChainArray();

        when(bundleSource.getX509BundleForTrustDomain(TrustDomain.of("example.org").getValue())).thenReturn(Result.ok(x509Bundle));

        try {
            trustManager.checkClientTrusted(chain, "");
            fail("CertificateException was expected");
        } catch (CertificateException e) {
            assertTrue(e.getMessage().contains("CertificateExpiredException: NotAfter"));
        }
    }

    @Test
    void checkClientTrusted_passCertificateWithNonAcceptedSpiffeId_ThrowCertificateException() {
        acceptedSpiffeIds =
                Collections
                        .singletonList(
                                SpiffeId.parse("spiffe://example.org/other").getValue()
                        );

        X509Certificate[] chain = x509Svid.getChainArray();

        when(bundleSource
                .getX509BundleForTrustDomain(
                        TrustDomain.of("example.org").getValue()))
                .thenReturn(Result.ok(x509Bundle));

        try {
            trustManager.checkClientTrusted(chain, "");
            fail("CertificateException was expected");
        } catch (CertificateException e) {
            assertEquals("SPIFFE ID 'spiffe://example.org/test' is not accepted", e.getMessage());
        }
    }

    @Test
    void checkClientTrusted_passCertificateThatDoesntChainToBundle_ThrowCertificateException() {
        acceptedSpiffeIds =
                Collections
                        .singletonList(
                                SpiffeId.parse("spiffe://other.org/test").getValue()
                        );

        val chain = otherX509Svid.getChainArray();

        when(bundleSource.getX509BundleForTrustDomain(TrustDomain.of("other.org").getValue())).thenReturn(Result.ok(x509Bundle));

        try {
            trustManager.checkClientTrusted(chain, "");
            fail("CertificateException was expected");
        } catch (CertificateException e) {
            assertTrue(e.getMessage().contains("CertPathValidatorException: Path does not chain with any of the trust anchors"));
        }
    }

    @Test
    void checkServerTrusted_passAnExpiredCertificate_ThrowsException() {
        acceptedSpiffeIds =
                Collections
                        .singletonList(
                                SpiffeId.parse("spiffe://example.org/test").getValue()
                        );

        val chain = x509Svid.getChainArray();

        when(bundleSource.getX509BundleForTrustDomain(TrustDomain.of("example.org").getValue())).thenReturn(Result.ok(x509Bundle));

        try {
            trustManager.checkServerTrusted(chain, "");
            fail("CertificateException was expected");
        } catch (CertificateException e) {
            assertTrue(e.getMessage().contains("CertificateExpiredException: NotAfter"));
        }
    }

    @Test
    void checkServerTrusted_passCertificateWithNonAcceptedSpiffeId_ThrowCertificateException() {
        acceptedSpiffeIds =
                Collections
                        .singletonList(
                                SpiffeId.parse("spiffe://example.org/other").getValue()
                        );

        val chain = x509Svid.getChainArray();

        when(bundleSource.getX509BundleForTrustDomain(TrustDomain.of("example.org").getValue())).thenReturn(Result.ok(x509Bundle));

        try {
            trustManager.checkServerTrusted(chain, "");
            fail("CertificateException was expected");
        } catch (CertificateException e) {
            assertEquals("SPIFFE ID 'spiffe://example.org/test' is not accepted", e.getMessage());
        }
    }

    @Test
    void checkServerTrusted_passCertificateThatDoesntChainToBundle_ThrowCertificateException() {
        acceptedSpiffeIds =
                Collections
                        .singletonList(
                                SpiffeId.parse("spiffe://other.org/test").getValue()
                        );

        val chain = otherX509Svid.getChainArray();

        when(bundleSource.getX509BundleForTrustDomain(TrustDomain.of("other.org").getValue())).thenReturn(Result.ok(x509Bundle));

        try {
            trustManager.checkServerTrusted(chain, "");
            fail("CertificateException was expected");
        } catch (CertificateException e) {
            assertTrue(e.getMessage().contains("CertPathValidatorException: Path does not chain with any of the trust anchors"));
        }
    }
}
