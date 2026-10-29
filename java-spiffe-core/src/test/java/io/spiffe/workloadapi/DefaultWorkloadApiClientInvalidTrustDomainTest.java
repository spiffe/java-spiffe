package io.spiffe.workloadapi;

import com.google.protobuf.ByteString;
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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultWorkloadApiClientInvalidTrustDomainTest {

    @Rule
    public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

    private DefaultWorkloadApiClient workloadApiClient;

    @BeforeEach
    void setUp() throws IOException {
        workloadApiClient = WorkloadApiClientTestUtil.create(
                new InvalidTrustDomainThenValidWorkloadApi(),
                grpcCleanup);
    }

    @AfterEach
    void tearDown() {
        workloadApiClient.close();
    }

    @Test
    void invalidTrustDomainReportsTypedErrorAndLaterUpdatesAreDelivered() throws InterruptedException {
        CountDownLatch errors = new CountDownLatch(3);
        CountDownLatch updates = new CountDownLatch(3);
        AtomicReference<Throwable> unexpectedError = new AtomicReference<>();

        workloadApiClient.watchX509Context(
                watcher(X509ContextException.class, errors, updates, unexpectedError));
        workloadApiClient.watchX509Bundles(
                watcher(X509BundleException.class, errors, updates, unexpectedError));
        workloadApiClient.watchJwtBundles(
                watcher(JwtBundleException.class, errors, updates, unexpectedError));

        assertTrue(errors.await(5, TimeUnit.SECONDS), "timed out waiting for rejected update errors");
        assertTrue(updates.await(5, TimeUnit.SECONDS), "timed out waiting for valid updates");
        assertNull(unexpectedError.get());
    }

    private static <T> Watcher<T> watcher(
            Class<? extends Throwable> expectedErrorType,
            CountDownLatch errors,
            CountDownLatch updates,
            AtomicReference<Throwable> unexpectedError) {
        return new Watcher<T>() {
            @Override
            public void onUpdate(T update) {
                updates.countDown();
            }

            @Override
            public void onError(Throwable error) {
                if (!expectedErrorType.isInstance(error)) {
                    unexpectedError.compareAndSet(null, error);
                }
                errors.countDown();
            }
        };
    }

    private static final class InvalidTrustDomainThenValidWorkloadApi extends FakeWorkloadApi {

        private static final String INVALID_TRUST_DOMAIN = "invalid/trust-domain";

        @Override
        public void fetchX509SVID(
                Workload.X509SVIDRequest request,
                StreamObserver<Workload.X509SVIDResponse> responseObserver) {
            super.fetchX509SVID(
                    request,
                    invalidThenValid(responseObserver, response -> {
                        ByteString bundle = response.getFederatedBundlesMap().values().iterator().next();
                        return response.toBuilder()
                                .putFederatedBundles(INVALID_TRUST_DOMAIN, bundle)
                                .build();
                    }));
        }

        @Override
        public void fetchX509Bundles(
                Workload.X509BundlesRequest request,
                StreamObserver<Workload.X509BundlesResponse> responseObserver) {
            super.fetchX509Bundles(
                    request,
                    invalidThenValid(responseObserver, response -> {
                        ByteString bundle = response.getBundlesMap().values().iterator().next();
                        return response.toBuilder()
                                .putBundles(INVALID_TRUST_DOMAIN, bundle)
                                .build();
                    }));
        }

        @Override
        public void fetchJWTBundles(
                Workload.JWTBundlesRequest request,
                StreamObserver<Workload.JWTBundlesResponse> responseObserver) {
            super.fetchJWTBundles(
                    request,
                    invalidThenValid(responseObserver, response -> {
                        ByteString bundle = response.getBundlesMap().values().iterator().next();
                        return response.toBuilder()
                                .putBundles(INVALID_TRUST_DOMAIN, bundle)
                                .build();
                    }));
        }

        private static <T> StreamObserver<T> invalidThenValid(
                StreamObserver<T> responseObserver,
                UnaryOperator<T> invalidUpdate) {
            return new StreamObserver<T>() {
                @Override
                public void onNext(T validUpdate) {
                    responseObserver.onNext(invalidUpdate.apply(validUpdate));
                    responseObserver.onNext(validUpdate);
                }

                @Override
                public void onError(Throwable error) {
                    responseObserver.onError(error);
                }

                @Override
                public void onCompleted() {
                    responseObserver.onCompleted();
                }
            };
        }
    }
}
