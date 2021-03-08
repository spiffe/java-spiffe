package io.spiffe.workloadapi;

import io.grpc.Status;
import io.grpc.testing.GrpcCleanupRule;
import io.spiffe.bundle.jwtbundle.JwtBundleSet;
import io.spiffe.bundle.x509bundle.X509BundleSet;
import io.spiffe.exception.X509ContextException;
import org.junit.Rule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

class DefaultWorkloadApiClientRetryableErrorTest {

    @Rule
    public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();
    private DefaultWorkloadApiClient workloadApiClient;

    @BeforeEach
    void setUp() throws IOException {
        workloadApiClient = WorkloadApiClientTestUtil.create(new FakeWorkloadApiExceptions(Status.UNAVAILABLE), grpcCleanup);
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
                assertEquals("Cancelling X.509 Context watch", e.getMessage());
                done.countDown();
            }
        };
        workloadApiClient.watchX509Context(contextWatcher);
        done.await();
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
                assertEquals("Cancelling X.509 bundles watch", e.getMessage());
                done.countDown();
            }
        };
        workloadApiClient.watchX509Bundles(contextWatcher);
        done.await();
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
                assertEquals("Cancelling JWT Bundles watch", e.getMessage());
                done.countDown();
            }
        };
        workloadApiClient.watchJwtBundles(contextWatcher);
        done.await();
    }
}