package io.spiffe.workloadapi;

import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.testing.GrpcCleanupRule;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.exception.X509SourceException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import org.junit.Rule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.svid.x509svid.X509Svid;
import io.spiffe.workloadapi.grpc.SpiffeWorkloadAPIGrpc;
import io.spiffe.workloadapi.internal.ManagedChannelWrapper;
import io.spiffe.workloadapi.internal.SecurityHeaderInterceptor;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class X509SourceTest {

    @Rule
    public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

    private X509Source x509Source;

    @BeforeEach
    void setUp() throws IOException, X509SourceException, SocketEndpointAddressException {
        // Generate a unique in-process server name.
        String serverName = InProcessServerBuilder.generateName();

        // Create a server, add service, start, and register for automatic graceful shutdown.
        FakeWorkloadApi fakeWorkloadApi = new FakeWorkloadApi();
        Server server = InProcessServerBuilder.forName(serverName).directExecutor().addService(fakeWorkloadApi).build().start();
        grpcCleanup.register(server);

        // Create WorkloadApiClient using Stubs that will connect to the fake WorkloadApiService.
        ManagedChannel inProcessChannel = InProcessChannelBuilder.forName(serverName).directExecutor().build();
        grpcCleanup.register(inProcessChannel);

        SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIBlockingStub workloadApiBlockingStub = SpiffeWorkloadAPIGrpc
                .newBlockingStub(inProcessChannel)
                .withInterceptors(new SecurityHeaderInterceptor());

        SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIStub workloadAPIStub = SpiffeWorkloadAPIGrpc
                .newStub(inProcessChannel)
                .withInterceptors(new SecurityHeaderInterceptor());

        WorkloadApiClient workloadApiClient = new WorkloadApiClient(workloadAPIStub, workloadApiBlockingStub, new ManagedChannelWrapper(inProcessChannel));
        X509Source.X509SourceOptions options = X509Source.X509SourceOptions.builder().workloadApiClient(workloadApiClient).build();
        x509Source = X509Source.newSource(options);
    }

    @AfterEach
    void tearDown() {
        x509Source.close();
    }

    @Test
    void testgetBundleForTrustDomain() {
        try {
            X509Bundle bundle = x509Source.getBundleForTrustDomain(TrustDomain.of("example.org"));
            assertNotNull(bundle);
            assertEquals(TrustDomain.of("example.org"), bundle.getTrustDomain());
        } catch (BundleNotFoundException e) {
            fail(e);
        }
    }

    @Test
    void testgetBundleForTrustDomain_SourceIsClosed_ThrowsIllegalStateExceptions() {
        x509Source.close();
        try {
            x509Source.getBundleForTrustDomain(TrustDomain.of("example.org"));
            fail("exceptions is expected");
        } catch (IllegalStateException e) {
            assertEquals("X.509 bundle source is closed", e.getMessage());
        } catch (BundleNotFoundException e) {
            fail("not expected exception", e);
        }
    }

    @Test
    void testGetX509Svid() {
        X509Svid x509Svid = x509Source.getX509Svid();
        assertNotNull(x509Svid);
        assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"),x509Svid.getSpiffeId());
    }

    @Test
    void testGetX509Svid_SourceIsClosed_ThrowsIllegalStateException() {
        x509Source.close();
        try {
            x509Source.getX509Svid();
            fail("exceptions is expected");
        } catch (IllegalStateException e) {
            assertEquals("X.509 SVID source is closed", e.getMessage());
        }
    }
}