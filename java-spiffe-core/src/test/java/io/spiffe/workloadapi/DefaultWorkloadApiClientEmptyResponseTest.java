package io.spiffe.workloadapi;

import io.grpc.testing.GrpcCleanupRule;
import io.spiffe.bundle.jwtbundle.JwtBundleSet;
import io.spiffe.bundle.x509bundle.X509BundleSet;
import io.spiffe.exception.JwtBundleException;
import io.spiffe.exception.JwtSvidException;
import io.spiffe.exception.X509BundleException;
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

class DefaultWorkloadApiClientEmptyResponseTest {

    @Rule
    public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();
    private DefaultWorkloadApiClient workloadApiClient;

    @BeforeEach
    void setUp() throws IOException {
        workloadApiClient = WorkloadApiClientTestUtil.create(new FakeWorkloadApiEmptyResponse(), grpcCleanup);
    }

    @AfterEach
    void tearDown() {
        workloadApiClient.close();
    }


    @Test
    void testFetchX509Context_throwsX509ContextException() throws Exception {
        try {
            workloadApiClient.fetchX509Context();
            fail();
        } catch (X509ContextException e) {
            assertEquals("Error fetching X509Context", e.getMessage());
        }
    }

    @Test
    void testWatchX509Context_onErrorIsCalledOnWatcher() throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        Watcher<X509Context> contextWatcher = new Watcher<X509Context>() {
            @Override
            public void onUpdate(X509Context update) {
                fail();
            }

            @Override
            public void onError(Throwable e) {
                assertEquals("Error processing X.509 Context update", e.getMessage());
                done.countDown();
            }
        };
        workloadApiClient.watchX509Context(contextWatcher);
        done.await();
    }

    @Test
    void testFetchX509Bundles_throwsX509BundleException() {
        try {
            workloadApiClient.fetchX509Bundles();
            fail();
        } catch (X509BundleException e) {
            assertEquals("Error fetching X.509 bundles", e.getMessage());
        }
    }

    @Test
    void testWatchX509Bundles_onErrorIsCalledOnWatched() throws InterruptedException {
        CountDownLatch done = new CountDownLatch(1);
        Watcher<X509BundleSet> contextWatcher = new Watcher<X509BundleSet>() {
            @Override
            public void onUpdate(X509BundleSet update) {
                fail();
            }

            @Override
            public void onError(Throwable e) {
                assertEquals("Error processing X.509 bundles update", e.getMessage());
                done.countDown();
            }
        };
        workloadApiClient.watchX509Bundles(contextWatcher);
        done.await();
    }

    @Test
    void testFetchJwtSvid_throwsJwtSvidException() {
        try {
            workloadApiClient.fetchJwtSvid("aud1", "aud2");
            fail();
        } catch (JwtSvidException e) {
            assertEquals("Error fetching JWT SVID", e.getMessage());
            assertEquals("JWT SVID response from the Workload API is empty", e.getCause().getMessage());
        }
    }

    @Test
    void testFetchJwtSvidPassingSpiffeId_throwsJwtSvidException() {
        try {
            workloadApiClient.fetchJwtSvid(SpiffeId.parse("spiffe://example.org/test"), "aud1", "aud2");
            fail();
        } catch (JwtSvidException e) {
            assertEquals("Error fetching JWT SVID", e.getMessage());
            assertEquals("JWT SVID response from the Workload API is empty", e.getCause().getMessage());
        }
    }

    @Test
    void testFetchJwtSvids_throwsJwtSvidException() {
        try {
            workloadApiClient.fetchJwtSvids("aud1", "aud2");
            fail();
        } catch (JwtSvidException e) {
            assertEquals("Error fetching JWT SVID", e.getMessage());
            assertEquals("JWT SVID response from the Workload API is empty", e.getCause().getMessage());
        }
    }

    @Test
    void testFetchJwtSvidsPassingSpiffeId_throwsJwtSvidException() {
        try {
            workloadApiClient.fetchJwtSvids(SpiffeId.parse("spiffe://example.org/test"), "aud1", "aud2");
            fail();
        } catch (JwtSvidException e) {
            assertEquals("Error fetching JWT SVID", e.getMessage());
            assertEquals("JWT SVID response from the Workload API is empty", e.getCause().getMessage());
        }
    }

    @Test
    void testValidateJwtSvid_throwsJwtSvidException() {
        try {
            workloadApiClient.validateJwtSvid("token", "aud1");
            fail();
        } catch (JwtSvidException e) {
            assertEquals("Error validating JWT SVID. Empty response from Workload API", e.getMessage());
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
        Watcher<JwtBundleSet> contextWatcher = new Watcher<JwtBundleSet>() {
            @Override
            public void onUpdate(JwtBundleSet update) {
                fail();
            }

            @Override
            public void onError(Throwable e) {
                assertEquals("Error processing JWT bundles update", e.getMessage());
                done.countDown();
            }
        };
        workloadApiClient.watchJwtBundles(contextWatcher);
        done.await();
    }
}