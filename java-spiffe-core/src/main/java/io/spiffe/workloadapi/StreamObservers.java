package io.spiffe.workloadapi;

import io.grpc.Context;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import io.spiffe.bundle.jwtbundle.JwtBundleSet;
import io.spiffe.exception.JwtBundleException;
import io.spiffe.exception.X509ContextException;
import io.spiffe.workloadapi.grpc.SpiffeWorkloadAPIGrpc;
import io.spiffe.workloadapi.grpc.Workload;
import io.spiffe.workloadapi.retry.RetryHandler;
import lombok.extern.java.Log;
import lombok.val;

import java.util.logging.Level;

@Log
final class StreamObservers {

    private static final String INVALID_ARGUMENT = "INVALID_ARGUMENT";

    private StreamObservers() {
    }

    static StreamObserver<Workload.X509SVIDResponse> getX509ContextStreamObserver(
            final Watcher<X509Context> watcher,
            final RetryHandler retryHandler,
            final Context.CancellableContext cancellableContext,
            final SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIStub workloadApiAsyncStub) {

        return new StreamObserver<Workload.X509SVIDResponse>() {
            @Override
            public void onNext(final Workload.X509SVIDResponse value) {
                try {
                    val x509Context = GrpcConversionUtils.toX509Context(value);
                    watcher.onUpdate(x509Context);
                    retryHandler.reset();
                } catch (X509ContextException e) {
                    watcher.onError(new X509ContextException("Error processing X.509 Context update", e));
                }
            }

            @Override
            public void onError(final Throwable t) {
                log.log(Level.SEVERE, "X.509 context observer error", t);
                handleWatchX509ContextError(t);
            }

            private void handleWatchX509ContextError(final Throwable t) {
                if (isErrorNotRetryable(t)) {
                    watcher.onError(new X509ContextException("Canceling X.509 Context watch", t));
                } else {
                    handleX509ContextRetry(t);
                }
            }

            private void handleX509ContextRetry(Throwable t) {
                if (retryHandler.shouldRetry()) {
                    log.log(Level.INFO, "Retrying connecting to Workload API to register X.509 context watcher");
                    retryHandler.scheduleRetry(() ->
                            cancellableContext.run(
                                    () -> workloadApiAsyncStub.fetchX509SVID(newX509SvidRequest(),
                                            this)));
                } else {
                    watcher.onError(new X509ContextException("Canceling X.509 Context watch", t));
                }
            }

            @Override
            public void onCompleted() {
                cancellableContext.close();
                log.info("Workload API stream is completed");
            }
        };
    }

    static StreamObserver<Workload.JWTBundlesResponse> getJwtBundleStreamObserver(
            final Watcher<JwtBundleSet> watcher,
            final RetryHandler retryHandler,
            final Context.CancellableContext cancellableContext,
            final SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIStub workloadApiAsyncStub) {
        return new StreamObserver<Workload.JWTBundlesResponse>() {

            @Override
            public void onNext(final Workload.JWTBundlesResponse value) {
                try {
                    val jwtBundleSet = GrpcConversionUtils.toBundleSet(value);
                    watcher.onUpdate(jwtBundleSet);
                    retryHandler.reset();
                } catch (JwtBundleException e) {
                    watcher.onError(new JwtBundleException("Error processing JWT bundles update", e));
                }
            }

            @Override
            public void onError(final Throwable t) {
                log.log(Level.SEVERE, "JWT observer error", t);
                handleWatchJwtBundleError(t);
            }

            private void handleWatchJwtBundleError(final Throwable t) {
                if (isErrorNotRetryable(t)) {
                    watcher.onError(new JwtBundleException("Canceling JWT Bundles watch", t));
                } else {
                    handleJwtBundleRetry(t);
                }
            }

            private void handleJwtBundleRetry(Throwable t) {
                if (retryHandler.shouldRetry()) {
                    log.log(Level.INFO, "Retrying connecting to Workload API to register JWT Bundles watcher");
                    retryHandler.scheduleRetry(() ->
                            cancellableContext.run(() -> workloadApiAsyncStub.fetchJWTBundles(newJwtBundlesRequest(),
                                    this)));
                } else {
                    watcher.onError(new JwtBundleException("Canceling JWT Bundles watch", t));
                }
            }

            @Override
            public void onCompleted() {
                cancellableContext.close();
                log.info("Workload API stream is completed");
            }
        };
    }

    private static boolean isErrorNotRetryable(Throwable t) {
        return INVALID_ARGUMENT.equals(Status.fromThrowable(t).getCode().name());
    }

    private static Workload.X509SVIDRequest newX509SvidRequest() {
        return Workload.X509SVIDRequest.newBuilder().build();
    }

    private static Workload.JWTBundlesRequest newJwtBundlesRequest() {
        return Workload.JWTBundlesRequest.newBuilder().build();
    }
}
