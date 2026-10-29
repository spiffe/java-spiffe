package io.spiffe.workloadapi;

import com.google.common.collect.Sets;
import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import io.grpc.testing.GrpcCleanupRule;
import io.spiffe.bundle.jwtbundle.JwtBundle;
import io.spiffe.bundle.jwtbundle.JwtBundleSet;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.exception.JwtBundleException;
import io.spiffe.exception.JwtSourceException;
import io.spiffe.exception.JwtSvidException;
import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.svid.jwtsvid.JwtSvid;
import io.spiffe.workloadapi.grpc.SpiffeWorkloadAPIGrpc;
import io.spiffe.workloadapi.grpc.Workload;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Collections;
import java.util.List;

import static io.spiffe.utils.TestUtils.toUri;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class DefaultJwtSourceTest {

    private JwtSource jwtSource;
    private WorkloadApiClientStub workloadApiClient;
    private WorkloadApiClientErrorStub workloadApiClientErrorStub;

    @BeforeEach
    void setUp() throws JwtSourceException, SocketEndpointAddressException {
        workloadApiClient = new WorkloadApiClientStub();
        JwtSourceOptions options = JwtSourceOptions.builder().workloadApiClient(workloadApiClient).build();
        System.setProperty(DefaultJwtSource.TIMEOUT_SYSTEM_PROPERTY, "PT1S");
        jwtSource = DefaultJwtSource.newSource(options);
        workloadApiClientErrorStub = new WorkloadApiClientErrorStub();
    }

    @AfterEach
    void tearDown() throws IOException {
        jwtSource.close();
    }

    @Test
    void testGetBundleForTrustDomain() {
        try {
            JwtBundle bundle = jwtSource.getBundleForTrustDomain(TrustDomain.parse("example.org"));
            assertNotNull(bundle);
            assertEquals(TrustDomain.parse("example.org"), bundle.getTrustDomain());
        } catch (BundleNotFoundException e) {
            fail(e);
        }
    }

    @Test
    void testGetBundleForTrustDomain_nullParam() {
        try {
            jwtSource.getBundleForTrustDomain(null);
            fail();
        } catch (NullPointerException e) {
            assertEquals("trustDomain must not be null", e.getMessage());
        } catch (BundleNotFoundException e) {
            fail();
        }
    }

    @Test
    void testGetBundleForTrustDomain_SourceIsClosed_ThrowsIllegalStateException() throws IOException {
        jwtSource.close();
        try {
            jwtSource.getBundleForTrustDomain(TrustDomain.parse("example.org"));
            fail("expected exception");
        } catch (IllegalStateException e) {
            assertEquals("JWT bundle source is closed", e.getMessage());
            assertTrue(workloadApiClient.closed);
        } catch (BundleNotFoundException e) {
            fail("not expected exception", e);
        }
    }

    @Test
    void testJwtBundlesWatcherError_afterInit_keepsBundlesAndAppliesLaterUpdates() throws BundleNotFoundException {
        TrustDomain trustDomain = TrustDomain.parse("example.org");
        JwtBundle initialBundle = jwtSource.getBundleForTrustDomain(trustDomain);

        workloadApiClient.jwtBundlesWatcher.onError(new JwtBundleException("Error processing JWT bundles update"));
        assertSame(initialBundle, jwtSource.getBundleForTrustDomain(trustDomain));

        JwtBundle updatedBundle = new JwtBundle(trustDomain);
        workloadApiClient.jwtBundlesWatcher.onUpdate(JwtBundleSet.of(Collections.singleton(updatedBundle)));
        assertSame(updatedBundle, jwtSource.getBundleForTrustDomain(trustDomain));
    }

    @Test
    void testWatchJwtBundles_unsupportedKeyTypeUpdate_laterUpdatesAreApplied() throws Exception {
        byte[] validBundle = Files.readAllBytes(Paths.get(toUri("testdata/workloadapi/bundle.json")));
        byte[] unsupportedKeyTypeBundle = Files.readAllBytes(Paths.get(toUri("testdata/jwtbundle/jwks_invalid_keytype.json")));
        SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIImplBase fakeWorkloadApi = new SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIImplBase() {
            @Override
            public void fetchJWTBundles(Workload.JWTBundlesRequest request, StreamObserver<Workload.JWTBundlesResponse> responseObserver) {
                responseObserver.onNext(newJwtBundlesResponse("example.org", validBundle));
                responseObserver.onNext(newJwtBundlesResponse("example.org", unsupportedKeyTypeBundle));
                responseObserver.onNext(newJwtBundlesResponse("domain.test", validBundle));
            }
        };
        DefaultWorkloadApiClient client = WorkloadApiClientTestUtil.create(fakeWorkloadApi, new GrpcCleanupRule());
        JwtSourceOptions options = JwtSourceOptions.builder().workloadApiClient(client).build();

        try (JwtSource source = DefaultJwtSource.newSource(options)) {
            JwtBundle bundle = source.getBundleForTrustDomain(TrustDomain.parse("domain.test"));
            assertEquals(TrustDomain.parse("domain.test"), bundle.getTrustDomain());
        }
    }

    @Test
    void testFetchJwtSvidWithSubject() {
        try {
            JwtSvid svid = jwtSource.fetchJwtSvid(SpiffeId.parse("spiffe://example.org/workload-server"), "aud1", "aud2", "aud3");
            assertNotNull(svid);
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svid.getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svid.getAudience());
            assertEquals("external", svid.getHint());
        } catch (JwtSvidException e) {
            fail(e);
        }
    }

    @Test
    void testFetchJwtSvidWithoutSubject() {
        try {
            JwtSvid svid = jwtSource.fetchJwtSvid("aud1", "aud2", "aud3");
            assertNotNull(svid);
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svid.getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svid.getAudience());
            assertEquals("external", svid.getHint());
        } catch (JwtSvidException e) {
            fail(e);
        }
    }

    @Test
    void testFetchJwtSvid_SourceIsClosed_ThrowsIllegalStateException() throws IOException {
        jwtSource.close();
        try {
            jwtSource.fetchJwtSvid("aud1", "aud2", "aud3");
            fail("expected exception");
        } catch (IllegalStateException e) {
            assertEquals("JWT SVID source is closed", e.getMessage());
            assertTrue(workloadApiClient.closed);
        } catch (JwtSvidException e) {
            fail(e);
        }
    }

    @Test
    void testFetchJwtSvidWithSubject_SourceIsClosed_ThrowsIllegalStateException() throws IOException {
        jwtSource.close();
        try {
            jwtSource.fetchJwtSvid(SpiffeId.parse("spiffe://example.org/workload-server"), "aud1", "aud2", "aud3");
            fail("expected exception");
        } catch (IllegalStateException e) {
            assertEquals("JWT SVID source is closed", e.getMessage());
            assertTrue(workloadApiClient.closed);
        } catch (JwtSvidException e) {
            fail(e);
        }
    }


    @Test
    void testFetchJwtSvidsWithSubject() {
        try {
            List<JwtSvid> svids = jwtSource.fetchJwtSvids(SpiffeId.parse("spiffe://example.org/workload-server"), "aud1", "aud2", "aud3");
            assertNotNull(svids);
            assertEquals(svids.size(), 1);
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svids.get(0).getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svids.get(0).getAudience());
        } catch (JwtSvidException e) {
            fail(e);
        }
    }

    @Test
    void testFetchJwtSvidsWithoutSubject() {
        try {
            List<JwtSvid> svids = jwtSource.fetchJwtSvids("aud1", "aud2", "aud3");
            assertNotNull(svids);
            assertEquals(2, svids.size());
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svids.get(0).getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svids.get(0).getAudience());
            assertEquals(SpiffeId.parse("spiffe://example.org/extra-workload-server"), svids.get(1).getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svids.get(1).getAudience());
        } catch (JwtSvidException e) {
            fail(e);
        }
    }


    @Test
    void testFetchJwtSvids_SourceIsClosed_ThrowsIllegalStateException() throws IOException {
        jwtSource.close();
        try {
            jwtSource.fetchJwtSvids("aud1", "aud2", "aud3");
            fail("expected exception");
        } catch (IllegalStateException e) {
            assertEquals("JWT SVID source is closed", e.getMessage());
            assertTrue(workloadApiClient.closed);
        } catch (JwtSvidException e) {
            fail(e);
        }
    }

    @Test
    void testFetchJwtSvidsWithSubject_SourceIsClosed_ThrowsIllegalStateException() throws IOException {
        jwtSource.close();
        try {
            jwtSource.fetchJwtSvids(SpiffeId.parse("spiffe://example.org/workload-server"), "aud1", "aud2", "aud3");
            fail("expected exception");
        } catch (IllegalStateException e) {
            assertEquals("JWT SVID source is closed", e.getMessage());
            assertTrue(workloadApiClient.closed);
        } catch (JwtSvidException e) {
            fail(e);
        }
    }

    @Test
    void newSource_success() {
        JwtSourceOptions options = JwtSourceOptions
                .builder()
                .workloadApiClient(workloadApiClient)
                .initTimeout(Duration.ofSeconds(0))
                .build();
        try {
            JwtSource jwtSource = DefaultJwtSource.newSource(options);
            assertNotNull(jwtSource);
        } catch (SocketEndpointAddressException | JwtSourceException e) {
            fail(e);
        }
    }

    @Test
    void newSource_nullParam() {
        try {
            DefaultJwtSource.newSource(null);
            fail();
        } catch (NullPointerException e) {
            assertEquals("options must not be null", e.getMessage());
        } catch (SocketEndpointAddressException | JwtSourceException e) {
            fail();
        }
    }

    @Test
    void newSource_errorFetchingJwtBundles() {
        JwtSourceOptions options = JwtSourceOptions
                .builder()
                .workloadApiClient(workloadApiClientErrorStub)
                .spiffeSocketPath("unix:/tmp/test")
                .build();
        try {
            DefaultJwtSource.newSource(options);
            fail();
        } catch (JwtSourceException e) {
            assertEquals("Error creating JWT source", e.getMessage());
            assertEquals("Error fetching JwtBundleSet", e.getCause().getMessage());
        } catch (Exception e) {
            fail();
        }
    }

    @Test
    void newSource_FailsBecauseOfTimeOut() throws Exception {
        try {
            JwtSourceOptions options = JwtSourceOptions
                    .builder()
                    .spiffeSocketPath("unix:/tmp/test")
                    .build();
            DefaultJwtSource.newSource(options);
            fail();
        } catch (JwtSourceException e) {
            assertEquals("Error creating JWT source", e.getMessage());
            assertEquals("Timeout waiting for JWT bundles update", e.getCause().getMessage());
        } catch (SocketEndpointAddressException e) {
            fail();
        }
    }

    @Test
    void newSource_DefaultSocketAddress() throws Exception {
        new EnvironmentVariables(Address.SOCKET_ENV_VARIABLE, "unix:/tmp/test").execute(() -> {
            try {
                DefaultJwtSource.newSource();
                fail();
            } catch (JwtSourceException e) {
                assertEquals("Error creating JWT source", e.getMessage());
            } catch (SocketEndpointAddressException e) {
                fail();
            }
        });
    }

    @Test
    void newSource_noSocketAddress() throws Exception {
        new EnvironmentVariables(Address.SOCKET_ENV_VARIABLE, "").execute(() -> {
            try {
                DefaultJwtSource.newSource();
                fail();
            } catch (SocketEndpointAddressException e) {
                fail();
            } catch (IllegalStateException e) {
                assertEquals("Endpoint Socket Address Environment Variable is not set: SPIFFE_ENDPOINT_SOCKET", e.getMessage());
            }
        });
    }

    private static Workload.JWTBundlesResponse newJwtBundlesResponse(String trustDomain, byte[] bundle) {
        return Workload.JWTBundlesResponse
                .newBuilder()
                .putBundles(trustDomain, ByteString.copyFrom(bundle))
                .build();
    }
}
