package io.spiffe.workloadapi;

import io.grpc.testing.GrpcCleanupRule;
import io.spiffe.exception.X509ContextException;
import org.junit.Rule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

class DefaultWorkloadApiClientMismatchSpiffeIdTest {

    @Rule
    public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();
    private DefaultWorkloadApiClient workloadApiClient;

    @BeforeEach
    void setUp() throws IOException {
        workloadApiClient = WorkloadApiClientTestUtil.create(new FakeWorkloadApiMismatchSpiffeId(), grpcCleanup);
    }

    @AfterEach
    void tearDown() {
        workloadApiClient.close();
    }


    @Test
    public void testFetchX509Context_throwsX509ContextException_whenSpiffeIdsMismatch() throws Exception {
        String expectedError =
                "SPIFFE ID in X509SVIDResponse (spiffe://wrong/domain/workload-server) does not match " +
                        "SPIFFE ID in X.509 certificate (spiffe://example.org/workload-server)";

        try {
            workloadApiClient.fetchX509Context();
            fail();
        } catch (X509ContextException e) {
            assertEquals("Error fetching X509Context", e.getMessage());
            assertEquals(expectedError, e.getCause().getMessage());
        }
    }
}