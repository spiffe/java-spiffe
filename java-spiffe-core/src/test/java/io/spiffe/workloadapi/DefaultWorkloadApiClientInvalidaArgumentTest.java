package io.spiffe.workloadapi;

import io.grpc.Status;
import io.grpc.testing.GrpcCleanupRule;
import io.spiffe.bundle.jwtbundle.JwtBundleSet;
import io.spiffe.exception.JwtBundleException;
import io.spiffe.exception.JwtSvidException;
import io.spiffe.exception.X509ContextException;
import io.spiffe.spiffeid.SpiffeId;
import org.junit.Rule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

class DefaultWorkloadApiClientInvalidaArgumentTest {

    @Rule
    public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();
    private DefaultWorkloadApiClient workloadApiClient;

    @BeforeEach
    void setUp() throws IOException {
        workloadApiClient = WorkloadApiClientTestUtil.create(new FakeWorkloadApiExceptions(Status.INVALID_ARGUMENT), grpcCleanup);
    }

    @AfterEach
    void tearDown() {
        workloadApiClient.close();
    }


    @Test
    public void testFetchX509Context_throwsX509ContextException() throws Exception {
        try {
            workloadApiClient.fetchX509Context();
            fail();
        } catch (X509ContextException e) {
            assertEquals("Error fetching X509Context", e.getMessage());
        }
    }

    @Test
    public void testWatchX509Context_onErrorIsCalledOnWatcher() throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        final String[] error = new String[1];
        Watcher<X509Context> contextWatcher = new Watcher<X509Context>() {
            @Override
            public void onUpdate(X509Context update) {
                fail();
            }

            @Override
            public void onError(Throwable e) {
                error[0] = e.getMessage();
                done.countDown();
            }
        };
        workloadApiClient.watchX509Context(contextWatcher);
        done.await();
        assertEquals("Canceling X.509 Context watch", error[0]);
    }

    @Test
    void testFetchJwtSvid_throwsJwtSvidException() {
        try {
            workloadApiClient.fetchJwtSvid("aud1", "aud2");
            fail();
        } catch (JwtSvidException e) {
            assertEquals("Error fetching JWT SVID", e.getMessage());
        }
    }

    @Test
    void testFetchJwtSvidPassingSpiffeId_throwsJwtSvidException() {
        try {
            workloadApiClient.fetchJwtSvid(SpiffeId.parse("spiffe://example.org/test"), "aud1", "aud2");
            fail();
        } catch (JwtSvidException e) {
            assertEquals("Error fetching JWT SVID", e.getMessage());
        }
    }

    @Test
    void testValidateJwtSvid_throwsJwtSvidException() {
        try {
            workloadApiClient.validateJwtSvid("token", "aud1");
            fail();
        } catch (JwtSvidException e) {
            assertEquals("Error validating JWT SVID", e.getMessage());
        }
    }

    @Test
    void testFetchJwtBundles_throwsJwtBundleException() {
        try {
            workloadApiClient.fetchJwtBundles();
            fail();
        } catch (JwtBundleException e) {
            assertEquals("Error fetching JWT Bundles", e.getMessage());
        }
    }

    @Test
    void testWatchJwtBundles_onErrorIsCalledOnWatched() throws InterruptedException {
        CountDownLatch done = new CountDownLatch(1);
        final String[] error = new String[1];
        Watcher<JwtBundleSet> contextWatcher = new Watcher<JwtBundleSet>() {
            @Override
            public void onUpdate(JwtBundleSet update) {
                fail();
            }

            @Override
            public void onError(Throwable e) {
                error[0] = e.getMessage();
                done.countDown();
            }
        };
        workloadApiClient.watchJwtBundles(contextWatcher);
        done.await();
        assertEquals("Canceling JWT Bundles watch", error[0]);
    }
}