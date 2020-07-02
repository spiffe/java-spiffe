package io.spiffe.workloadapi;

import com.nimbusds.jose.jwk.Curve;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.testing.GrpcCleanupRule;
import io.spiffe.bundle.jwtbundle.JwtBundle;
import io.spiffe.bundle.jwtbundle.JwtBundleSet;
import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.exception.JwtBundleException;
import io.spiffe.exception.JwtSvidException;
import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.svid.jwtsvid.JwtSvid;
import io.spiffe.utils.TestUtils;
import io.spiffe.workloadapi.grpc.SpiffeWorkloadAPIGrpc;
import io.spiffe.workloadapi.internal.ManagedChannelWrapper;
import io.spiffe.workloadapi.internal.SecurityHeaderInterceptor;
import io.spiffe.workloadapi.retry.ExponentialBackoffPolicy;
import org.junit.Rule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.KeyPair;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class DefaultWorkloadApiClientTest {

    @Rule
    public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();
    private DefaultWorkloadApiClient workloadApiClient;

    @BeforeEach
    void setUp() throws IOException {
        // Generate a unique in-process server name.
        String serverName = InProcessServerBuilder.generateName();

        // Create a server, add service, start, and register for automatic graceful shutdown.
        FakeWorkloadApi fakeWorkloadApi = new FakeWorkloadApi();
        Server server = InProcessServerBuilder.forName(serverName).directExecutor().addService(fakeWorkloadApi).build().start();
        grpcCleanup.register(server);

        // Create WorkloadApiClient using Stubs that will connect to the fake WorkloadApiService.
        final ManagedChannel inProcessChannel = InProcessChannelBuilder.forName(serverName).directExecutor().build();
        grpcCleanup.register(inProcessChannel);

        SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIBlockingStub workloadApiBlockingStub = SpiffeWorkloadAPIGrpc
                .newBlockingStub(inProcessChannel)
                .withInterceptors(new SecurityHeaderInterceptor());

        SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIStub workloadAPIStub = SpiffeWorkloadAPIGrpc
                .newStub(inProcessChannel)
                .withInterceptors(new SecurityHeaderInterceptor());

        workloadApiClient = new DefaultWorkloadApiClient(workloadAPIStub, workloadApiBlockingStub, new ManagedChannelWrapper(inProcessChannel));
    }

    @AfterEach
    void tearDown() {
        workloadApiClient.close();
    }

    @Test
    void testNewClient_defaultOptions() throws Exception {
        try {
            TestUtils.setEnvironmentVariable(Address.SOCKET_ENV_VARIABLE, "unix:/tmp/agent.sock" );
            WorkloadApiClient client = DefaultWorkloadApiClient.newClient();
            assertNotNull(client);
        } catch (SocketEndpointAddressException e) {
            fail(e);
        }
    }

    @Test
    void testNewClient_customOptions() {
        try {
            DefaultWorkloadApiClient.ClientOptions options =
                    DefaultWorkloadApiClient.ClientOptions
                            .builder()
                            .spiffeSocketPath("unix:/tmp/agent.sock")
                            .executorService(Executors.newCachedThreadPool())
                            .exponentialBackoffPolicy(ExponentialBackoffPolicy.DEFAULT)
                            .build();

            WorkloadApiClient client = DefaultWorkloadApiClient.newClient(options);
            assertNotNull(client);
        } catch (SocketEndpointAddressException e) {
            fail(e);
        }
    }

    @Test
    public void testFetchX509Context() throws Exception {

        X509Context x509Context = workloadApiClient.fetchX509Context();

        assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), x509Context.getDefaultSvid().getSpiffeId());
        assertNotNull(x509Context.getDefaultSvid().getChain());
        assertNotNull(x509Context.getDefaultSvid().getPrivateKey());
        assertNotNull(x509Context.getX509BundleSet());
        try {
            X509Bundle bundle = x509Context.getX509BundleSet().getBundleForTrustDomain(TrustDomain.of("example.org"));
            assertNotNull(bundle);
        } catch (BundleNotFoundException e) {
            fail(e);
        }
    }

    @Test
    void testWatchX509Context() throws InterruptedException {
        CountDownLatch done = new CountDownLatch(1);
        final X509Context[] x509Context = new X509Context[1];
        Watcher<X509Context> contextWatcher = new Watcher<X509Context>() {
            @Override
            public void onUpdate(X509Context update) {
                x509Context[0] = update;
                done.countDown();

            }

            @Override
            public void onError(Throwable e) {
            }
        };

        workloadApiClient.watchX509Context(contextWatcher);
        done.await();

        X509Context update = x509Context[0];
        assertNotNull(update);
        assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), update.getDefaultSvid().getSpiffeId());
        assertNotNull(update.getDefaultSvid().getChain());
        assertNotNull(update.getDefaultSvid().getPrivateKey());
        assertNotNull(update.getX509BundleSet());
        try {
            X509Bundle bundle = update.getX509BundleSet().getBundleForTrustDomain(TrustDomain.of("example.org"));
            assertNotNull(bundle);
        } catch (BundleNotFoundException e) {
            fail(e);
        }
    }

    @Test
    void testFetchJwtSvid() {
        try {
            JwtSvid jwtSvid = workloadApiClient.fetchJwtSvid(SpiffeId.parse("spiffe://example.org/workload-server"), "aud1", "aud2", "aud3");
            assertNotNull(jwtSvid);
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), jwtSvid.getSpiffeId());
            assertTrue(jwtSvid.getAudience().contains("aud1"));
            assertEquals(3, jwtSvid.getAudience().size());
        } catch (JwtSvidException e) {
            fail(e);
        }
    }

    @Test
    void testValidateJwtSvid() {
        String token = generateToken("spiffe://example.org/workload-server", Collections.singletonList("aud1"));
        try {
            JwtSvid jwtSvid = workloadApiClient.validateJwtSvid(token, "aud1");
            assertNotNull(jwtSvid);
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), jwtSvid.getSpiffeId());
            assertTrue(jwtSvid.getAudience().contains("aud1"));
            assertEquals(1, jwtSvid.getAudience().size());
        } catch (JwtSvidException e) {
            fail(e);
        }
    }

    @Test
    void testFetchJwtBundles() {

        JwtBundleSet jwtBundleSet = null;
        try {
            jwtBundleSet = workloadApiClient.fetchJwtBundles();
        } catch (JwtBundleException e) {
            fail(e);
        }

        assertNotNull(jwtBundleSet);
        try {
            JwtBundle bundle = jwtBundleSet.getBundleForTrustDomain(TrustDomain.of("example.org"));
            assertNotNull(bundle);
            assertEquals(3, bundle.getJwtAuthorities().size());
        } catch (BundleNotFoundException e) {
            fail(e);
        }
    }

    @Test
    void testWatchJwtBundles() throws InterruptedException {
        CountDownLatch done = new CountDownLatch(1);

        final JwtBundleSet[] jwtBundleSet = new JwtBundleSet[1];

        Watcher<JwtBundleSet> jwtBundleSetWatcher = new Watcher<JwtBundleSet>() {
            @Override
            public void onUpdate(JwtBundleSet update) {
                jwtBundleSet[0] = update;
                done.countDown();

            }
            @Override
            public void onError(Throwable e) {
            }
        };

        workloadApiClient.watchJwtBundles(jwtBundleSetWatcher);
        done.await();

        JwtBundleSet update = jwtBundleSet[0];
        assertNotNull(update);
        try {
            JwtBundle bundle = update.getBundleForTrustDomain(TrustDomain.of("example.org"));
            assertNotNull(bundle);
            assertEquals(3, bundle.getJwtAuthorities().size());
        } catch (BundleNotFoundException e) {
            fail(e);
        }
    }

    private String generateToken(String sub, List<String> aud) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", sub);
        claims.put("aud", aud);
        Date expiration = new Date(System.currentTimeMillis() + 3600000);
        claims.put("exp", expiration);

        KeyPair keyPair = TestUtils.generateECKeyPair(Curve.P_256);
        return TestUtils.generateToken(claims, keyPair, "authority1");
    }

}