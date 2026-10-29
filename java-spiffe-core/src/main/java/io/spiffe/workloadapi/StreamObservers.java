package io.spiffe.workloadapi;

import io.grpc.Context;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import io.spiffe.bundle.jwtbundle.JwtBundleSet;
import io.spiffe.bundle.x509bundle.X509BundleSet;
import io.spiffe.exception.JwtBundleException;
import io.spiffe.exception.X509BundleException;
import io.spiffe.exception.X509ContextException;
import io.spiffe.workloadapi.grpc.SpiffeWorkloadAPIGrpc;
import io.spiffe.workloadapi.grpc.Workload;
import io.spiffe.workloadapi.retry.RetryHandler;

import java.util.EnumSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

final class StreamObservers {

    private static final Logger log =
            Logger.getLogger(StreamObservers.class.getName());

    private static final String STREAM_IS_COMPLETED = "Workload API stream is completed";
    // PermissionDenied is retryable, but must be reported after an update has been delivered.
    // Caller/client cancellation and terminal API errors fail the watch closed.
    private static final Set<Status.Code> NON_RETRYABLE_CODES = EnumSet.of(
            Status.Code.INVALID_ARGUMENT,
            Status.Code.CANCELLED,
            Status.Code.UNAUTHENTICATED,
            Status.Code.UNIMPLEMENTED,
            Status.Code.FAILED_PRECONDITION);

    private StreamObservers() {
    }

    static StreamObserver<Workload.X509SVIDResponse> getX509ContextStreamObserver(
            final Watcher<X509Context> watcher,
            final RetryHandler retryHandler,
            final Context.CancellableContext cancellableContext,
            final SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIStub workloadApiAsyncStub) {

        return new StreamObserver<Workload.X509SVIDResponse>() {
            private boolean updateDelivered;
            private boolean permissionDeniedReported;

            @Override
            public void onNext(final Workload.X509SVIDResponse value) {
                try {
                    final X509Context x509Context = GrpcConversionUtils.toX509Context(value);
                    watcher.onUpdate(x509Context);
                    updateDelivered = true;
                    permissionDeniedReported = false;
                    retryHandler.reset();
                } catch (X509ContextException e) {
                    watcher.onError(new X509ContextException("Error processing X.509 Context update", e));
                }
            }

            @Override
            public void onError(final Throwable t) {
                if (Status.fromThrowable(t).getCode() != Status.Code.CANCELLED) {
                    log.log(Level.SEVERE, "X.509 context observer error", t);
                }
                handleWatchX509ContextError(t);
            }

            private void handleWatchX509ContextError(final Throwable t) {
                if (isErrorNotRetryable(t)) {
                    watcher.onError(new X509ContextException("Cancelling X.509 Context watch", t));
                } else {
                    if (updateDelivered && !permissionDeniedReported
                            && Status.fromThrowable(t).getCode() == Status.Code.PERMISSION_DENIED) {
                        permissionDeniedReported = true;
                        watcher.onError(new X509ContextException("Permission denied for X.509 Context watch", t));
                    }
                    handleX509ContextRetry(t);
                }
            }

            private void handleX509ContextRetry(Throwable t) {
                if (retryHandler.shouldRetry()) {
                    log.log(Level.FINE, "Retrying connecting to Workload API to register X.509 context watcher");
                    boolean retryScheduled = retryHandler.tryScheduleRetry(() ->
                            cancellableContext.run(
                                    () -> workloadApiAsyncStub.fetchX509SVID(newX509SvidRequest(),
                                            this)));
                    if (retryScheduled) {
                        return;
                    }
                }
                if (!permissionDeniedReported || Status.fromThrowable(t).getCode() != Status.Code.PERMISSION_DENIED) {
                    watcher.onError(new X509ContextException("Cancelling X.509 Context watch", t));
                }
            }

            @Override
            public void onCompleted() {
                cancellableContext.close();
                log.info(STREAM_IS_COMPLETED);
            }
        };
    }

    static StreamObserver<Workload.X509BundlesResponse> getX509BundlesStreamObserver(
            final Watcher<X509BundleSet> watcher,
            final RetryHandler retryHandler,
            final Context.CancellableContext cancellableContext,
            final SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIStub workloadApiAsyncStub) {

        return new StreamObserver<Workload.X509BundlesResponse>() {
            private boolean updateDelivered;
            private boolean permissionDeniedReported;

            @Override
            public void onNext(final Workload.X509BundlesResponse value) {
                try {
                    final X509BundleSet x509Context = GrpcConversionUtils.toX509BundleSet(value);
                    watcher.onUpdate(x509Context);
                    updateDelivered = true;
                    permissionDeniedReported = false;
                    retryHandler.reset();
                } catch (X509BundleException e) {
                    watcher.onError(new X509BundleException("Error processing X.509 bundles update", e));
                }
            }

            @Override
            public void onError(final Throwable t) {
                if (Status.fromThrowable(t).getCode() != Status.Code.CANCELLED) {
                    log.log(Level.SEVERE, "X.509 bundles observer error", t);
                }
                handleWatchX509BundlesError(t);
            }

            private void handleWatchX509BundlesError(final Throwable t) {
                if (isErrorNotRetryable(t)) {
                    watcher.onError(new X509BundleException("Cancelling X.509 bundles watch", t));
                } else {
                    if (updateDelivered && !permissionDeniedReported
                            && Status.fromThrowable(t).getCode() == Status.Code.PERMISSION_DENIED) {
                        permissionDeniedReported = true;
                        watcher.onError(new X509BundleException("Permission denied for X.509 bundles watch", t));
                    }
                    handleX509BundlesRetry(t);
                }
            }

            private void handleX509BundlesRetry(Throwable t) {
                if (retryHandler.shouldRetry()) {
                    log.log(Level.FINE, "Retrying connecting to Workload API to register X.509 bundles watcher");
                    boolean retryScheduled = retryHandler.tryScheduleRetry(() ->
                            cancellableContext.run(
                                    () -> workloadApiAsyncStub.fetchX509Bundles(newX509BundlesRequest(),
                                            this)));
                    if (retryScheduled) {
                        return;
                    }
                }
                if (!permissionDeniedReported || Status.fromThrowable(t).getCode() != Status.Code.PERMISSION_DENIED) {
                    watcher.onError(new X509BundleException("Cancelling X.509 bundles watch", t));
                }
            }

            @Override
            public void onCompleted() {
                cancellableContext.close();
                log.info(STREAM_IS_COMPLETED);
            }
        };
    }

    static StreamObserver<Workload.JWTBundlesResponse> getJwtBundleStreamObserver(
            final Watcher<JwtBundleSet> watcher,
            final RetryHandler retryHandler,
            final Context.CancellableContext cancellableContext,
            final SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIStub workloadApiAsyncStub) {
        return new StreamObserver<Workload.JWTBundlesResponse>() {
            private boolean updateDelivered;
            private boolean permissionDeniedReported;

            @Override
            public void onNext(final Workload.JWTBundlesResponse value) {
                try {
                    final JwtBundleSet jwtBundleSet = GrpcConversionUtils.toJwtBundleSet(value);
                    watcher.onUpdate(jwtBundleSet);
                    updateDelivered = true;
                    permissionDeniedReported = false;
                    retryHandler.reset();
                } catch (JwtBundleException e) {
                    watcher.onError(new JwtBundleException("Error processing JWT bundles update", e));
                }
            }

            @Override
            public void onError(final Throwable t) {
                if (Status.fromThrowable(t).getCode() != Status.Code.CANCELLED) {
                    log.log(Level.SEVERE, "JWT observer error", t);
                }
                handleWatchJwtBundleError(t);
            }

            private void handleWatchJwtBundleError(final Throwable t) {
                if (isErrorNotRetryable(t)) {
                    watcher.onError(new JwtBundleException("Cancelling JWT Bundles watch", t));
                } else {
                    if (updateDelivered && !permissionDeniedReported
                            && Status.fromThrowable(t).getCode() == Status.Code.PERMISSION_DENIED) {
                        permissionDeniedReported = true;
                        watcher.onError(new JwtBundleException("Permission denied for JWT Bundles watch", t));
                    }
                    handleJwtBundleRetry(t);
                }
            }

            private void handleJwtBundleRetry(Throwable t) {
                if (retryHandler.shouldRetry()) {
                    log.log(Level.FINE, "Retrying connecting to Workload API to register JWT Bundles watcher");
                    boolean retryScheduled = retryHandler.tryScheduleRetry(() ->
                            cancellableContext.run(() -> workloadApiAsyncStub.fetchJWTBundles(newJwtBundlesRequest(),
                                    this)));
                    if (retryScheduled) {
                        return;
                    }
                }
                if (!permissionDeniedReported || Status.fromThrowable(t).getCode() != Status.Code.PERMISSION_DENIED) {
                    watcher.onError(new JwtBundleException("Cancelling JWT Bundles watch", t));
                }
            }

            @Override
            public void onCompleted() {
                cancellableContext.close();
                log.info(STREAM_IS_COMPLETED);
            }
        };
    }

    private static boolean isErrorNotRetryable(Throwable t) {
        return NON_RETRYABLE_CODES.contains(Status.fromThrowable(t).getCode());
    }

    private static Workload.X509SVIDRequest newX509SvidRequest() {
        return Workload.X509SVIDRequest.newBuilder().build();
    }

    private static Workload.X509BundlesRequest newX509BundlesRequest() {
        return Workload.X509BundlesRequest.newBuilder().build();
    }

    private static Workload.JWTBundlesRequest newJwtBundlesRequest() {
        return Workload.JWTBundlesRequest.newBuilder().build();
    }
}
