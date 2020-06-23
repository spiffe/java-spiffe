package io.spiffe.provider;

import io.spiffe.bundle.BundleSource;
import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.exception.X509SvidException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.svid.x509svid.X509Svid;
import lombok.val;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.when;

public class SpiffeTrustManagerTest {

    @Mock
    BundleSource bundleSource;

    static X509Bundle x509Bundle;
    static X509Svid x509Svid;
    static X509Svid otherX509Svid;
    Set<SpiffeId> acceptedSpiffeIds;
    X509TrustManager trustManager;

    @BeforeAll
    static void setupClass() throws IOException, CertificateException, X509SvidException, URISyntaxException {
        x509Svid = X509Svid
                .load(
                        Paths.get(toUri("testdata/cert.pem")),
                        Paths.get(toUri("testdata/key.pem")));
        otherX509Svid = X509Svid
                .load(
                        Paths.get(toUri("testdata/cert2.pem")),
                        Paths.get(toUri("testdata/key2.pem")));
        x509Bundle = X509Bundle
                .load(
                        TrustDomain.of("example.org"),
                        Paths.get(toUri("testdata/bundle.pem")));
    }

    @BeforeEach
    void setupMocks() {
        MockitoAnnotations.initMocks(this);
        trustManager = (X509TrustManager)
                new SpiffeTrustManagerFactory().engineGetTrustManagers(bundleSource, () -> acceptedSpiffeIds)[0];
    }

    @Test
    void checkClientTrusted_passAExpiredCertificate_throwsException() throws BundleNotFoundException {
        acceptedSpiffeIds = Collections.singleton(SpiffeId.parse("spiffe://example.org/test"));

        val chain = x509Svid.getChainArray();

        when(bundleSource.getBundleForTrustDomain(TrustDomain.of("example.org"))).thenReturn(x509Bundle);

        try {
            trustManager.checkClientTrusted(chain, "");
            fail("CertificateException was expected");
        } catch (CertificateException e) {
            assertEquals("Cert chain cannot be verified", e.getMessage());
        }
    }

    @Test
    void checkClientTrusted_noBundleForTrustDomain_ThrowCertificateException() throws BundleNotFoundException {
        acceptedSpiffeIds = Collections.singleton(SpiffeId.parse("spiffe://example.org/test"));

        val chain = x509Svid.getChainArray();

        when(bundleSource.getBundleForTrustDomain(TrustDomain.of("example.org"))).thenThrow(new BundleNotFoundException("Bundle not found"));

        try {
            trustManager.checkClientTrusted(chain, "");
            fail("CertificateException was expected");
        } catch (CertificateException e) {
            assertEquals("Bundle not found", e.getMessage());
        }
    }

    @Test
    void checkClientTrusted_passCertificateWithNonAcceptedSpiffeId_ThrowCertificateException() throws BundleNotFoundException {
        acceptedSpiffeIds = Collections.singleton(SpiffeId.parse("spiffe://example.org/other"));

        X509Certificate[] chain = x509Svid.getChainArray();

        when(bundleSource.getBundleForTrustDomain(TrustDomain.of("example.org")))
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
        acceptedSpiffeIds = Collections.singleton(SpiffeId.parse("spiffe://other.org/test"));

        val chain = otherX509Svid.getChainArray();

        when(bundleSource.getBundleForTrustDomain(TrustDomain.of("other.org"))).thenReturn(x509Bundle);

        try {
            trustManager.checkClientTrusted(chain, "");
            fail("CertificateException was expected");
        } catch (CertificateException e) {
            assertEquals("Cert chain cannot be verified", e.getMessage());
        }
    }

    @Test
    void checkServerTrusted_passAnExpiredCertificate_ThrowsException() throws BundleNotFoundException {
        acceptedSpiffeIds = Collections.singleton(SpiffeId.parse("spiffe://example.org/test"));

        val chain = x509Svid.getChainArray();

        when(bundleSource.getBundleForTrustDomain(TrustDomain.of("example.org"))).thenReturn(x509Bundle);

        try {
            trustManager.checkServerTrusted(chain, "");
            fail("CertificateException was expected");
        } catch (CertificateException e) {
            assertEquals("Cert chain cannot be verified", e.getMessage());
        }
    }

    @Test
    void checkServerTrusted_passCertificateWithNonAcceptedSpiffeId_ThrowCertificateException() throws BundleNotFoundException {
        acceptedSpiffeIds = Collections.singleton(SpiffeId.parse("spiffe://example.org/other"));

        val chain = x509Svid.getChainArray();

        when(bundleSource.getBundleForTrustDomain(TrustDomain.of("example.org"))).thenReturn(x509Bundle);

        try {
            trustManager.checkServerTrusted(chain, "");
            fail("CertificateException was expected");
        } catch (CertificateException e) {
            assertEquals("SPIFFE ID spiffe://example.org/test in X.509 certificate is not accepted", e.getMessage());
        }
    }

    @Test
    void checkServerTrusted_passCertificateThatDoesntChainToBundle_ThrowCertificateException() throws BundleNotFoundException {
        acceptedSpiffeIds = Collections.singleton(SpiffeId.parse("spiffe://other.org/test"));

        val chain = otherX509Svid.getChainArray();

        when(bundleSource.getBundleForTrustDomain(TrustDomain.of("other.org"))).thenReturn(x509Bundle);

        try {
            trustManager.checkServerTrusted(chain, "");
            fail("CertificateException was expected");
        } catch (CertificateException e) {
            assertEquals("Cert chain cannot be verified", e.getMessage());
        }
    }

    private static URI toUri(String path) throws URISyntaxException {
        return Thread.currentThread().getContextClassLoader().getResource(path).toURI();
    }
}
