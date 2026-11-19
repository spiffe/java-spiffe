package io.spiffe.provider;

import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.svid.x509svid.X509Svid;
import io.spiffe.utils.CertAndKeyPair;
import io.spiffe.workloadapi.X509Source;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static io.spiffe.utils.X509CertificateTestUtils.createCertificate;
import static io.spiffe.utils.X509CertificateTestUtils.createRootCA;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

class SpiffeSslContextFactoryTest {

    X509Source x509Source;

    @BeforeEach
    void setup() {
        x509Source = new X509SourceStub();
    }

    @Test
    void getSslContext_withX509Source() {
        SpiffeSslContextFactory.SslContextOptions options =
                SpiffeSslContextFactory.SslContextOptions
                        .builder()
                        .x509Source(x509Source)
                        .acceptAnySpiffeId()
                        .build();
        try {
            assertNotNull(SpiffeSslContextFactory.getSslContext(options));
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            fail(e);
        }
    }

    @Test
    void getSslContext_withSupplierOfSpiffeIds() {
        SpiffeSslContextFactory.SslContextOptions options =
                SpiffeSslContextFactory.SslContextOptions
                        .builder()
                        .x509Source(x509Source)
                        .acceptedSpiffeIdsSupplier(Collections::emptySet)
                        .build();
        try {
            assertNotNull(SpiffeSslContextFactory.getSslContext(options));
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            fail(e);
        }
    }

    @Test
    void getSslContext_withAcceptAny() {
        SpiffeSslContextFactory.SslContextOptions options =
                SpiffeSslContextFactory.SslContextOptions
                        .builder()
                        .x509Source(x509Source)
                        .acceptAnySpiffeId()
                        .build();
        try {
            assertNotNull(SpiffeSslContextFactory.getSslContext(options));
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            fail(e);
        }
    }

    @Test
    void getSslContext_withOtherSslProtocol() {
        SpiffeSslContextFactory.SslContextOptions options =
                SpiffeSslContextFactory.SslContextOptions
                        .builder()
                        .x509Source(x509Source)
                        .acceptAnySpiffeId()
                        .sslProtocol("TLSv1.1")
                        .build();
        try {
            assertNotNull(SpiffeSslContextFactory.getSslContext(options));
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            fail(e);
        }
    }

    @Test
    void getSslContext_nullOptions() throws KeyManagementException, NoSuchAlgorithmException {
        try {
            SpiffeSslContextFactory.getSslContext(null);
        } catch (NullPointerException e) {
            assertEquals("options must not be null", e.getMessage());
        }
    }

    @Test
    void getSslContext_nullX509Source() throws KeyManagementException, NoSuchAlgorithmException {
        SpiffeSslContextFactory.SslContextOptions options =
                SpiffeSslContextFactory.SslContextOptions
                        .builder()
                        .acceptAnySpiffeId()
                        .build();
        try {
            SpiffeSslContextFactory.getSslContext(options);
        } catch (IllegalArgumentException e) {
            assertEquals("x509Source option must not be null, an X.509 Source must be provided", e.getMessage());
        }
    }

    @Test
    void getSslContext_noSupplierAndAcceptAnyNotSet() {
        SpiffeSslContextFactory.SslContextOptions options =
                SpiffeSslContextFactory.SslContextOptions
                        .builder()
                        .x509Source(x509Source)
                        .build();
        try {
            SpiffeSslContextFactory.getSslContext(options);
            fail();
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            fail(e);
        } catch (IllegalArgumentException e) {
            assertEquals("SSL context should be configured either with a SPIFFE ID verifier, " +
                    "with a Supplier of accepted SPIFFE IDs or with acceptAnySpiffeId=true", e.getMessage());
        }
    }

    @Test
    void getSslContext_withSpiffeIdVerifier() {
        SpiffeIdVerifier spiffeIdVerifier = (spiffeId, verifiedChain) -> {
        };
        SpiffeSslContextFactory.SslContextOptions options =
                SpiffeSslContextFactory.SslContextOptions
                        .builder()
                        .x509Source(x509Source)
                        .spiffeIdVerifier(spiffeIdVerifier)
                        .build();

        assertSame(spiffeIdVerifier, options.getSpiffeIdVerifier());
        try {
            assertNotNull(SpiffeSslContextFactory.getSslContext(options));
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            fail(e);
        }
    }

    @Test
    void getSslContext_spiffeIdVerifierAndSupplierOfSpiffeIds() {
        SpiffeSslContextFactory.SslContextOptions options =
                SpiffeSslContextFactory.SslContextOptions
                        .builder()
                        .x509Source(x509Source)
                        .spiffeIdVerifier((spiffeId, verifiedChain) -> {
                        })
                        .acceptedSpiffeIdsSupplier(Collections::emptySet)
                        .build();

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> SpiffeSslContextFactory.getSslContext(options));
        assertEquals("SSL context should not be configured with a SPIFFE ID verifier " +
                "together with a Supplier of accepted SPIFFE IDs or with acceptAnySpiffeId=true", e.getMessage());
    }

    @Test
    void getSslContext_spiffeIdVerifierAndAcceptAny() {
        SpiffeSslContextFactory.SslContextOptions options =
                SpiffeSslContextFactory.SslContextOptions
                        .builder()
                        .x509Source(x509Source)
                        .spiffeIdVerifier((spiffeId, verifiedChain) -> {
                        })
                        .acceptAnySpiffeId()
                        .build();

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> SpiffeSslContextFactory.getSslContext(options));
        assertEquals("SSL context should not be configured with a SPIFFE ID verifier " +
                "together with a Supplier of accepted SPIFFE IDs or with acceptAnySpiffeId=true", e.getMessage());
    }

    @Test
    void getSslContext_spiffeIdVerifierIsCalledWithPeerSpiffeIdAndChain() throws Exception {
        TrustDomain trustDomain = TrustDomain.parse("example.org");
        CertAndKeyPair rootCa = createRootCA("C = US, O = SPIFFE", trustDomain.toIdString());
        X509Source clientSource = newX509Source(trustDomain, rootCa, "client");
        X509Source serverSource = newX509Source(trustDomain, rootCa, "server");

        Map<SpiffeId, X509Certificate[]> verifiedPeers = new HashMap<>();
        SpiffeIdVerifier recordingVerifier = verifiedPeers::put;

        SSLContext clientContext = SpiffeSslContextFactory.getSslContext(
                SpiffeSslContextFactory.SslContextOptions.builder()
                        .x509Source(clientSource)
                        .spiffeIdVerifier(recordingVerifier)
                        .build());
        SSLContext serverContext = SpiffeSslContextFactory.getSslContext(
                SpiffeSslContextFactory.SslContextOptions.builder()
                        .x509Source(serverSource)
                        .spiffeIdVerifier(recordingVerifier)
                        .build());

        handshake(clientContext, serverContext);

        assertEquals(2, verifiedPeers.size());
        assertArrayEquals(serverSource.getX509Svid().getChainArray(),
                verifiedPeers.get(SpiffeId.parse("spiffe://example.org/server")));
        assertArrayEquals(clientSource.getX509Svid().getChainArray(),
                verifiedPeers.get(SpiffeId.parse("spiffe://example.org/client")));
    }

    @Test
    void getSslContext_spiffeIdVerifierRejectsPeer() throws Exception {
        TrustDomain trustDomain = TrustDomain.parse("example.org");
        CertAndKeyPair rootCa = createRootCA("C = US, O = SPIFFE", trustDomain.toIdString());
        X509Source clientSource = newX509Source(trustDomain, rootCa, "client");
        X509Source serverSource = newX509Source(trustDomain, rootCa, "server");

        SSLContext clientContext = SpiffeSslContextFactory.getSslContext(
                SpiffeSslContextFactory.SslContextOptions.builder()
                        .x509Source(clientSource)
                        .spiffeIdVerifier((spiffeId, verifiedChain) -> {
                            throw new SpiffeVerificationException(
                                    String.format("SPIFFE ID %s is not authorized", spiffeId));
                        })
                        .build());
        SSLContext serverContext = SpiffeSslContextFactory.getSslContext(
                SpiffeSslContextFactory.SslContextOptions.builder()
                        .x509Source(serverSource)
                        .acceptAnySpiffeId()
                        .build());

        SSLHandshakeException e = assertThrows(SSLHandshakeException.class,
                () -> handshake(clientContext, serverContext));
        Throwable cause = e;
        while (cause != null && !(cause instanceof SpiffeVerificationException)) {
            cause = cause.getCause();
        }
        assertNotNull(cause, "the handshake should fail because the SPIFFE ID verifier rejects the server");
        assertEquals("SPIFFE ID spiffe://example.org/server is not authorized", cause.getMessage());
    }

    @Test
    void getSslContext_spiffeIdVerifierFactories() throws Exception {
        TrustDomain trustDomain = TrustDomain.parse("example.org");
        CertAndKeyPair rootCa = createRootCA("C = US, O = SPIFFE", trustDomain.toIdString());
        X509Source clientSource = newX509Source(trustDomain, rootCa, "client");
        X509Source serverSource = newX509Source(trustDomain, rootCa, "server");

        SSLContext clientContext = SpiffeSslContextFactory.getSslContext(
                SpiffeSslContextFactory.SslContextOptions.builder()
                        .x509Source(clientSource)
                        .spiffeIdVerifier(SpiffeIdVerifier.acceptId(SpiffeId.parse("spiffe://example.org/server")))
                        .build());
        SSLContext serverContext = SpiffeSslContextFactory.getSslContext(
                SpiffeSslContextFactory.SslContextOptions.builder()
                        .x509Source(serverSource)
                        .spiffeIdVerifier(SpiffeIdVerifier.acceptMemberOf(trustDomain))
                        .build());

        handshake(clientContext, serverContext);

        SSLContext rejectingClientContext = SpiffeSslContextFactory.getSslContext(
                SpiffeSslContextFactory.SslContextOptions.builder()
                        .x509Source(clientSource)
                        .spiffeIdVerifier(SpiffeIdVerifier.acceptOneOf(SpiffeId.parse("spiffe://example.org/other")))
                        .build());

        SSLHandshakeException e = assertThrows(SSLHandshakeException.class,
                () -> handshake(rejectingClientContext, serverContext));
        Throwable cause = e;
        while (cause != null && !(cause instanceof SpiffeVerificationException)) {
            cause = cause.getCause();
        }
        assertNotNull(cause, "the handshake should fail because the SPIFFE ID verifier rejects the server");
        assertEquals("SPIFFE ID spiffe://example.org/server in X.509 certificate is not accepted", cause.getMessage());
    }

    private static X509Source newX509Source(TrustDomain trustDomain, CertAndKeyPair rootCa, String path)
            throws Exception {
        CertAndKeyPair leaf = createCertificate("C = US, O = SPIRE", "C = US, O = SPIFFE",
                SpiffeId.fromSegments(trustDomain, path).toString(), rootCa, false);
        X509Svid svid = X509Svid.parseRaw(
                leaf.getCertificate().getEncoded(),
                leaf.getKeyPair().getPrivate().getEncoded());
        X509Bundle bundle = new X509Bundle(trustDomain, Collections.singleton(rootCa.getCertificate()));

        return new X509Source() {
            @Override
            public X509Svid getX509Svid() {
                return svid;
            }

            @Override
            public X509Bundle getBundleForTrustDomain(TrustDomain bundleTrustDomain)
                    throws BundleNotFoundException {
                return bundle.getBundleForTrustDomain(bundleTrustDomain);
            }

            @Override
            public void close() {
            }
        };
    }

    // Runs a mutual TLS handshake between two in-memory SSLEngines.
    private static void handshake(SSLContext clientContext, SSLContext serverContext) throws SSLException {
        SSLEngine client = clientContext.createSSLEngine();
        client.setUseClientMode(true);
        SSLEngine server = serverContext.createSSLEngine();
        server.setUseClientMode(false);
        server.setNeedClientAuth(true);

        int packetBufferSize = client.getSession().getPacketBufferSize();
        int applicationBufferSize = client.getSession().getApplicationBufferSize();
        ByteBuffer clientToServer = ByteBuffer.allocate(packetBufferSize);
        ByteBuffer serverToClient = ByteBuffer.allocate(packetBufferSize);
        ByteBuffer clientIn = ByteBuffer.allocate(applicationBufferSize);
        ByteBuffer serverIn = ByteBuffer.allocate(applicationBufferSize);
        ByteBuffer empty = ByteBuffer.allocate(0);

        client.beginHandshake();
        server.beginHandshake();
        for (int i = 0; i < 100 && (isHandshaking(client) || isHandshaking(server)); i++) {
            client.wrap(empty, clientToServer);
            runDelegatedTasks(client);
            server.wrap(empty, serverToClient);
            runDelegatedTasks(server);

            clientToServer.flip();
            serverToClient.flip();
            client.unwrap(serverToClient, clientIn);
            runDelegatedTasks(client);
            server.unwrap(clientToServer, serverIn);
            runDelegatedTasks(server);
            clientToServer.compact();
            serverToClient.compact();
        }

        if (isHandshaking(client) || isHandshaking(server)) {
            fail("TLS handshake did not complete");
        }
    }

    private static boolean isHandshaking(SSLEngine engine) {
        return engine.getHandshakeStatus() != HandshakeStatus.NOT_HANDSHAKING;
    }

    private static void runDelegatedTasks(SSLEngine engine) {
        Runnable task;
        while ((task = engine.getDelegatedTask()) != null) {
            task.run();
        }
    }
}