package io.spiffe.provider;

import io.spiffe.bundle.BundleSource;
import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import lombok.val;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Set;

import static io.spiffe.utils.X509CertificateTestUtils.createCertificate;
import static io.spiffe.utils.X509CertificateTestUtils.createRootCA;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.when;

public class SpiffeTrustManagerTest {

    @Mock
    BundleSource<X509Bundle> bundleSource;

    static X509Certificate[] chain;
    static X509Bundle bundleKnown;
    static X509Bundle bundleUnknown;

    Set<SpiffeId> acceptedSpiffeIds;

    SpiffeTrustManager spiffeTrustManager;

    @BeforeAll
    static void setupClass() throws Exception {
        val subject = "C = US, O = SPIRE";
        val issuerSubject = "C = US, O = SPIFFE";

        val trustDomain = TrustDomain.parse("spiffe://example.org");
        val spiffeIdRoot = trustDomain.newSpiffeId();
        val spiffeIdHost1 = SpiffeId.of(trustDomain, "/host1");
        val spiffeIdHost2 = SpiffeId.of(trustDomain, "/host2");
        val spiffeIdTest = SpiffeId.of(trustDomain, "/test");

        val rootCa = createRootCA(issuerSubject, spiffeIdRoot.toString() );
        val otherRootCa = createRootCA(issuerSubject, spiffeIdRoot.toString());

        val intermediate1 = createCertificate(subject, issuerSubject,  spiffeIdHost1.toString(), rootCa, true);
        val intermediate2 = createCertificate(subject, subject,  spiffeIdHost2.toString(), intermediate1, true);
        val leaf = createCertificate(subject, subject,  spiffeIdTest.toString(), intermediate2, false);

        chain = new X509Certificate[]{leaf.getCertificate(), intermediate2.getCertificate(), intermediate1.getCertificate()};

        bundleKnown = X509Bundle.parse(trustDomain, rootCa.getCertificate().getEncoded());
        bundleUnknown = X509Bundle.parse(trustDomain, otherRootCa.getCertificate().getEncoded());
    }

    @BeforeEach
    void setupMocks() {
        MockitoAnnotations.initMocks(this);
        spiffeTrustManager = new SpiffeTrustManager(bundleSource, () -> acceptedSpiffeIds);
    }

    @Test
    void testCreateSpiffeTrustManager_nullSource() {
        try {
            new SpiffeTrustManager(null);
            fail();
        } catch (Exception e) {
            assertEquals("x509BundleSource is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testCreateSpiffeTrustManager_nullSupplier() {
        try {
            new SpiffeTrustManager(bundleSource, null);
            fail();
        } catch (Exception e) {
            assertEquals("acceptedSpiffeIdsSupplier is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testCreateSpiffeTrustManager_nullParameters() {
        try {
            new SpiffeTrustManager(null, null);
            fail();
        } catch (Exception e) {
            assertEquals("x509BundleSource is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void test_checkClientTrustedMethods_Success() throws BundleNotFoundException {
        acceptedSpiffeIds = Collections.singleton(SpiffeId.parse("spiffe://example.org/test"));
        when(bundleSource.getBundleForTrustDomain(TrustDomain.parse("example.org"))).thenReturn(bundleKnown);

        try {
            spiffeTrustManager.checkClientTrusted(chain, "");
            spiffeTrustManager.checkClientTrusted(chain, "", new Socket());
            spiffeTrustManager.checkClientTrusted(chain, "", getSslEngineStub());
        } catch (CertificateException e) {
            fail(e);
        }
    }

    @Test
    void test_checkClientTrustedMethods_ChainCannotVerify() throws BundleNotFoundException {
        acceptedSpiffeIds = Collections.singleton(SpiffeId.parse("spiffe://example.org/test"));
        when(bundleSource.getBundleForTrustDomain(TrustDomain.parse("example.org"))).thenReturn(bundleUnknown);

        try {
            spiffeTrustManager.checkClientTrusted(chain, "");
            fail();
        } catch (CertificateException e) {
            assertEquals("Cert chain cannot be verified", e.getMessage());
        }

        try {
            spiffeTrustManager.checkClientTrusted(chain, "", new Socket());
            fail();
        } catch (CertificateException e) {
            assertEquals("Cert chain cannot be verified", e.getMessage());
        }

        try {
            spiffeTrustManager.checkClientTrusted(chain, "", getSslEngineStub());
            fail();
        } catch (CertificateException e) {
            assertEquals("Cert chain cannot be verified", e.getMessage());
        }
    }

    @Test
    void test_checkClientTrustedMethods_ChainIsNull() throws CertificateException {
        try {
            spiffeTrustManager.checkClientTrusted(null, "");
            fail();
        } catch (NullPointerException e) {
            assertEquals("chain is marked non-null but is null", e.getMessage());
        }

        try {
            spiffeTrustManager.checkClientTrusted(null, "", new Socket());
            fail();
        } catch (NullPointerException e) {
            assertEquals("chain is marked non-null but is null", e.getMessage());
        }

        try {
            spiffeTrustManager.checkClientTrusted(null, "", getSslEngineStub());
            fail();
        } catch (NullPointerException e) {
            assertEquals("chain is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void test_checkServerTrustedMethods_Success() throws BundleNotFoundException {
        acceptedSpiffeIds = Collections.singleton(SpiffeId.parse("spiffe://example.org/test"));
        when(bundleSource.getBundleForTrustDomain(TrustDomain.parse("example.org"))).thenReturn(bundleKnown);

        try {
            spiffeTrustManager.checkServerTrusted(chain, "");
            spiffeTrustManager.checkServerTrusted(chain, "", new Socket());
            spiffeTrustManager.checkServerTrusted(chain, "", getSslEngineStub());
        } catch (CertificateException e) {
            fail(e);
        }
    }

    @Test
    void test_checkServerTrustedMethods_ChainCannotVerify() throws BundleNotFoundException {
        acceptedSpiffeIds = Collections.singleton(SpiffeId.parse("spiffe://example.org/test"));
        when(bundleSource.getBundleForTrustDomain(TrustDomain.parse("example.org"))).thenReturn(bundleUnknown);

        try {
            spiffeTrustManager.checkServerTrusted(chain, "");
            fail();
        } catch (CertificateException e) {
            assertEquals("Cert chain cannot be verified", e.getMessage());
        }

        try {
            spiffeTrustManager.checkServerTrusted(chain, "", new Socket());
            fail();
        } catch (CertificateException e) {
            assertEquals("Cert chain cannot be verified", e.getMessage());
        }

        try {
            spiffeTrustManager.checkServerTrusted(chain, "", getSslEngineStub());
            fail();
        } catch (CertificateException e) {
            assertEquals("Cert chain cannot be verified", e.getMessage());
        }
    }

    @Test
    void test_checkServerTrustedMethods_ChainIsNull() throws CertificateException {
        try {
            spiffeTrustManager.checkServerTrusted(null, "");
            fail();
        } catch (NullPointerException e) {
            assertEquals("chain is marked non-null but is null", e.getMessage());
        }

        try {
            spiffeTrustManager.checkServerTrusted(null, "", new Socket());
            fail();
        } catch (NullPointerException e) {
            assertEquals("chain is marked non-null but is null", e.getMessage());
        }

        try {
            spiffeTrustManager.checkServerTrusted(null, "", getSslEngineStub());
            fail();
        } catch (NullPointerException e) {
            assertEquals("chain is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void checkClientTrusted_noBundleForTrustDomain_ThrowCertificateException() throws BundleNotFoundException {
        acceptedSpiffeIds = Collections.singleton(SpiffeId.parse("spiffe://example.org/test"));

        when(bundleSource.getBundleForTrustDomain(TrustDomain.parse("example.org"))).thenThrow(new BundleNotFoundException("Bundle not found"));

        try {
            spiffeTrustManager.checkClientTrusted(chain, "");
            fail();
        } catch (CertificateException e) {
            assertEquals("Bundle not found", e.getMessage());
        }
    }

    @Test
    void checkServerTrusted_noBundleForTrustDomain_ThrowCertificateException() throws BundleNotFoundException {
        acceptedSpiffeIds = Collections.singleton(SpiffeId.parse("spiffe://example.org/test"));
        when(bundleSource.getBundleForTrustDomain(TrustDomain.parse("example.org"))).thenThrow(new BundleNotFoundException("Bundle not found"));

        try {
            spiffeTrustManager.checkServerTrusted(chain, "");
            fail();
        } catch (CertificateException e) {
            assertEquals("Bundle not found", e.getMessage());
        }
    }

    @Test
    void checkClientTrusted_passCertificateWithNonAcceptedSpiffeId_ThrowCertificateException() throws BundleNotFoundException {
        acceptedSpiffeIds = Collections.singleton(SpiffeId.parse("spiffe://example.org/other"));
        when(bundleSource.getBundleForTrustDomain(TrustDomain.parse("example.org"))).thenReturn(bundleKnown);

        try {
            spiffeTrustManager.checkClientTrusted(chain, "");
            fail("CertificateException was expected");
        } catch (CertificateException e) {
            assertEquals("SPIFFE ID spiffe://example.org/test in X.509 certificate is not accepted", e.getMessage());
        }
    }

    @Test
    void checkClientTrusted_acceptyAnySpiffeId() throws BundleNotFoundException {
        acceptedSpiffeIds = Collections.singleton(SpiffeId.parse("spiffe://example.org/other"));
        when(bundleSource.getBundleForTrustDomain(TrustDomain.parse("example.org"))).thenReturn(bundleKnown);

        spiffeTrustManager = new SpiffeTrustManager(bundleSource);

        try {
            spiffeTrustManager.checkClientTrusted(chain, "");
        } catch (CertificateException e) {
            fail(e);
        }
    }

    @Test
    void checkServerTrusted_acceptyAnySpiffeId() throws BundleNotFoundException {
        acceptedSpiffeIds = Collections.singleton(SpiffeId.parse("spiffe://example.org/other"));
        when(bundleSource.getBundleForTrustDomain(TrustDomain.parse("example.org"))).thenReturn(bundleKnown);

        spiffeTrustManager = new SpiffeTrustManager(bundleSource);

        try {
            spiffeTrustManager.checkClientTrusted(chain, "");
        } catch (CertificateException e) {
            fail(e);
        }
    }

    @Test
    void checkServerTrusted_passCertificateWithNonAcceptedSpiffeId_ThrowCertificateException() throws BundleNotFoundException {
        acceptedSpiffeIds = Collections.singleton(SpiffeId.parse("spiffe://example.org/other"));
        when(bundleSource.getBundleForTrustDomain(TrustDomain.parse("example.org"))).thenReturn(bundleKnown);

        try {
            spiffeTrustManager.checkServerTrusted(chain, "");
            fail("CertificateException was expected");
        } catch (CertificateException e) {
            assertEquals("SPIFFE ID spiffe://example.org/test in X.509 certificate is not accepted", e.getMessage());
        }
    }

    @Test
    void getAcceptedIssuers() {
        X509Certificate[] acceptedIssuers = spiffeTrustManager.getAcceptedIssuers();
        assertEquals(0, acceptedIssuers.length);
    }

    private SSLEngine getSslEngineStub() {
        return new SSLEngine() {
            @Override
            public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) throws SSLException {
                return null;
            }

            @Override
            public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length) throws SSLException {
                return null;
            }

            @Override
            public Runnable getDelegatedTask() {
                return null;
            }

            @Override
            public void closeInbound() throws SSLException {

            }

            @Override
            public boolean isInboundDone() {
                return false;
            }

            @Override
            public void closeOutbound() {

            }

            @Override
            public boolean isOutboundDone() {
                return false;
            }

            @Override
            public String[] getSupportedCipherSuites() {
                return new String[0];
            }

            @Override
            public String[] getEnabledCipherSuites() {
                return new String[0];
            }

            @Override
            public void setEnabledCipherSuites(String[] suites) {

            }

            @Override
            public String[] getSupportedProtocols() {
                return new String[0];
            }

            @Override
            public String[] getEnabledProtocols() {
                return new String[0];
            }

            @Override
            public void setEnabledProtocols(String[] protocols) {

            }

            @Override
            public SSLSession getSession() {
                return null;
            }

            @Override
            public void beginHandshake() throws SSLException {

            }

            @Override
            public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
                return null;
            }

            @Override
            public void setUseClientMode(boolean mode) {

            }

            @Override
            public boolean getUseClientMode() {
                return false;
            }

            @Override
            public void setNeedClientAuth(boolean need) {

            }

            @Override
            public boolean getNeedClientAuth() {
                return false;
            }

            @Override
            public void setWantClientAuth(boolean want) {

            }

            @Override
            public boolean getWantClientAuth() {
                return false;
            }

            @Override
            public void setEnableSessionCreation(boolean flag) {

            }

            @Override
            public boolean getEnableSessionCreation() {
                return false;
            }
        };
    }
}
