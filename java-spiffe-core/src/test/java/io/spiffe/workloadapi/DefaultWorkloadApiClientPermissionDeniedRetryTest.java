package io.spiffe.workloadapi;

import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import io.grpc.testing.GrpcCleanupRule;
import io.spiffe.bundle.jwtbundle.JwtBundleSet;
import io.spiffe.bundle.x509bundle.X509BundleSet;
import io.spiffe.exception.JwtBundleException;
import io.spiffe.exception.X509BundleException;
import io.spiffe.exception.X509ContextException;
import io.spiffe.workloadapi.grpc.Workload;
import org.junit.Rule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultWorkloadApiClientPermissionDeniedRetryTest {

    @Rule
    public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

    private PermissionDeniedThenSuccessWorkloadApi fakeWorkloadApi;
    private DefaultWorkloadApiClient workloadApiClient;

    @BeforeEach
    void setUp() throws IOException {
        fakeWorkloadApi = new PermissionDeniedThenSuccessWorkloadApi();
        workloadApiClient = WorkloadApiClientTestUtil.create(fakeWorkloadApi, grpcCleanup);
    }

    @AfterEach
    void tearDown() {
        workloadApiClient.close();
    }

    @Test
    void permissionDeniedRetriesAllWatchesUntilAnUpdateIsReceived() throws InterruptedException {
        CountDownLatch updates = new CountDownLatch(3);
        AtomicReference<Throwable> watchError = new AtomicReference<>();

        workloadApiClient.watchX509Context(watcher(updates, watchError));
        workloadApiClient.watchX509Bundles(watcher(updates, watchError));
        workloadApiClient.watchJwtBundles(watcher(updates, watchError));

        assertTrue(updates.await(5, TimeUnit.SECONDS), "timed out waiting for retried watch updates");
        assertNull(watchError.get());
        assertEquals(2, fakeWorkloadApi.x509ContextRequests.get());
        assertEquals(2, fakeWorkloadApi.x509BundleRequests.get());
        assertEquals(2, fakeWorkloadApi.jwtBundleRequests.get());
    }

    @Test
    void permissionDeniedAfterUpdateReportsTypedErrorAndRetriesAllWatches() throws InterruptedException {
        fakeWorkloadApi.sendUpdateBeforeDenial = true;
        CountDownLatch updates = new CountDownLatch(6);
        List<String> x509ContextEvents = new CopyOnWriteArrayList<>();
        List<String> x509BundleEvents = new CopyOnWriteArrayList<>();
        List<String> jwtBundleEvents = new CopyOnWriteArrayList<>();

        workloadApiClient.watchX509Context(recordingWatcher(updates, x509ContextEvents));
        workloadApiClient.watchX509Bundles(recordingWatcher(updates, x509BundleEvents));
        workloadApiClient.watchJwtBundles(recordingWatcher(updates, jwtBundleEvents));

        assertTrue(updates.await(5, TimeUnit.SECONDS), "timed out waiting for updates after permission denial");
        assertEquals(Arrays.asList("update", X509ContextException.class.getName(), "update"), x509ContextEvents);
        assertEquals(Arrays.asList("update", X509BundleException.class.getName(), "update"), x509BundleEvents);
        assertEquals(Arrays.asList("update", JwtBundleException.class.getName(), "update"), jwtBundleEvents);
        assertEquals(2, fakeWorkloadApi.x509ContextRequests.get());
        assertEquals(2, fakeWorkloadApi.x509BundleRequests.get());
        assertEquals(2, fakeWorkloadApi.jwtBundleRequests.get());
    }

    private static <T> Watcher<T> recordingWatcher(CountDownLatch updates, List<String> events) {
        return new Watcher<T>() {
            @Override
            public void onUpdate(T update) {
                events.add("update");
                updates.countDown();
            }

            @Override
            public void onError(Throwable error) {
                events.add(error.getClass().getName());
            }
        };
    }

    private static <T> Watcher<T> watcher(
            CountDownLatch updates,
            AtomicReference<Throwable> watchError) {
        return new Watcher<T>() {
            @Override
            public void onUpdate(T update) {
                updates.countDown();
            }

            @Override
            public void onError(Throwable error) {
                watchError.compareAndSet(null, error);
            }
        };
    }

    private static final class PermissionDeniedThenSuccessWorkloadApi extends FakeWorkloadApi {

        private boolean sendUpdateBeforeDenial;
        private final AtomicInteger x509ContextRequests = new AtomicInteger();
        private final AtomicInteger x509BundleRequests = new AtomicInteger();
        private final AtomicInteger jwtBundleRequests = new AtomicInteger();

        @Override
        public void fetchX509SVID(
                Workload.X509SVIDRequest request,
                StreamObserver<Workload.X509SVIDResponse> responseObserver) {
            if (x509ContextRequests.incrementAndGet() == 1) {
                if (sendUpdateBeforeDenial) {
                    super.fetchX509SVID(request, permissionDeniedOnCompletion(responseObserver));
                } else {
                    responseObserver.onError(Status.PERMISSION_DENIED.asRuntimeException());
                }
                return;
            }
            super.fetchX509SVID(request, responseObserver);
        }

        @Override
        public void fetchX509Bundles(
                Workload.X509BundlesRequest request,
                StreamObserver<Workload.X509BundlesResponse> responseObserver) {
            if (x509BundleRequests.incrementAndGet() == 1) {
                if (sendUpdateBeforeDenial) {
                    super.fetchX509Bundles(request, permissionDeniedOnCompletion(responseObserver));
                } else {
                    responseObserver.onError(Status.PERMISSION_DENIED.asRuntimeException());
                }
                return;
            }
            super.fetchX509Bundles(request, responseObserver);
        }

        @Override
        public void fetchJWTBundles(
                Workload.JWTBundlesRequest request,
                StreamObserver<Workload.JWTBundlesResponse> responseObserver) {
            if (jwtBundleRequests.incrementAndGet() == 1) {
                if (sendUpdateBeforeDenial) {
                    super.fetchJWTBundles(request, permissionDeniedOnCompletion(responseObserver));
                } else {
                    responseObserver.onError(Status.PERMISSION_DENIED.asRuntimeException());
                }
                return;
            }
            super.fetchJWTBundles(request, responseObserver);
        }

        private static <T> StreamObserver<T> permissionDeniedOnCompletion(StreamObserver<T> observer) {
            return new StreamObserver<T>() {
                @Override
                public void onNext(T value) {
                    observer.onNext(value);
                }

                @Override
                public void onError(Throwable error) {
                    observer.onError(error);
                }

                @Override
                public void onCompleted() {
                    observer.onError(Status.PERMISSION_DENIED.asRuntimeException());
                }
            };
        }
    }
}
