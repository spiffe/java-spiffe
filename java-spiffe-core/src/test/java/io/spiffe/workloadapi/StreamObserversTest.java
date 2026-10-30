package io.spiffe.workloadapi;

import io.grpc.Context;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import io.spiffe.bundle.jwtbundle.JwtBundleSet;
import io.spiffe.bundle.x509bundle.X509BundleSet;
import io.spiffe.exception.JwtBundleException;
import io.spiffe.exception.X509BundleException;
import io.spiffe.exception.X509ContextException;
import io.spiffe.workloadapi.grpc.Workload;
import io.spiffe.workloadapi.retry.RetryHandler;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class StreamObserversTest {

    @ParameterizedTest
    @EnumSource(WatchType.class)
    @SuppressWarnings({"rawtypes", "unchecked"})
    void permissionDeniedAfterUpdateReportsOnceBeforeRetrying(WatchType watchType) {
        Watcher watcher = mock(Watcher.class);
        RetryHandler retryHandler = mock(RetryHandler.class);
        when(retryHandler.shouldRetry()).thenReturn(true);
        when(retryHandler.tryScheduleRetry(any(Runnable.class))).thenReturn(true);
        Throwable denial = Status.PERMISSION_DENIED.asRuntimeException();

        Context.CancellableContext context = Context.current().withCancellation();
        try {
            StreamObserver<?> observer = newStreamObserver(watchType, watcher, retryHandler, context);
            deliverUpdate(watchType, observer);
            observer.onError(denial);
            observer.onError(Status.PERMISSION_DENIED.asRuntimeException());

            InOrder order = inOrder(watcher, retryHandler);
            order.verify(watcher).onUpdate(any());
            order.verify(retryHandler).reset();
            order.verify(watcher).onError(any(Throwable.class));
            order.verify(retryHandler).shouldRetry();
            order.verify(retryHandler).tryScheduleRetry(any(Runnable.class));
            order.verify(retryHandler).shouldRetry();
            order.verify(retryHandler).tryScheduleRetry(any(Runnable.class));
            order.verifyNoMoreInteractions();
            assertWatcherError(watcher, watchType, denial);
        } finally {
            context.close();
        }
    }

    @ParameterizedTest
    @EnumSource(WatchType.class)
    @SuppressWarnings({"rawtypes", "unchecked"})
    void successfulUpdateAllowsAnotherPermissionDeniedNotification(WatchType watchType) {
        Watcher watcher = mock(Watcher.class);
        RetryHandler retryHandler = mock(RetryHandler.class);
        when(retryHandler.shouldRetry()).thenReturn(true);
        when(retryHandler.tryScheduleRetry(any(Runnable.class))).thenReturn(true);
        Throwable firstDenial = Status.PERMISSION_DENIED.asRuntimeException();
        Throwable secondDenial = Status.PERMISSION_DENIED.asRuntimeException();

        Context.CancellableContext context = Context.current().withCancellation();
        try {
            StreamObserver<?> observer = newStreamObserver(watchType, watcher, retryHandler, context);
            deliverUpdate(watchType, observer);
            observer.onError(firstDenial);
            deliverUpdate(watchType, observer);
            observer.onError(secondDenial);

            ArgumentCaptor<Throwable> errors = ArgumentCaptor.forClass(Throwable.class);
            InOrder order = inOrder(watcher);
            order.verify(watcher).onUpdate(any());
            order.verify(watcher).onError(errors.capture());
            order.verify(watcher).onUpdate(any());
            order.verify(watcher).onError(errors.capture());
            order.verifyNoMoreInteractions();
            assertInstanceOf(watchType.errorType, errors.getAllValues().get(0));
            assertSame(firstDenial, errors.getAllValues().get(0).getCause());
            assertInstanceOf(watchType.errorType, errors.getAllValues().get(1));
            assertSame(secondDenial, errors.getAllValues().get(1).getCause());
            verify(retryHandler, times(2)).tryScheduleRetry(any(Runnable.class));
        } finally {
            context.close();
        }
    }

    @ParameterizedTest
    @MethodSource("permissionDeniedRetryFailureCases")
    @SuppressWarnings("rawtypes")
    void permissionDeniedRetryFailureDoesNotDuplicateNotification(WatchType watchType, boolean shouldRetry) {
        Watcher watcher = mock(Watcher.class);
        RetryHandler retryHandler = mock(RetryHandler.class);
        when(retryHandler.shouldRetry()).thenReturn(shouldRetry);
        if (shouldRetry) {
            when(retryHandler.tryScheduleRetry(any(Runnable.class))).thenReturn(false);
        }
        Throwable denial = Status.PERMISSION_DENIED.asRuntimeException();

        Context.CancellableContext context = Context.current().withCancellation();
        try {
            StreamObserver<?> observer = newStreamObserver(watchType, watcher, retryHandler, context);
            deliverUpdate(watchType, observer);
            observer.onError(denial);

            assertWatcherError(watcher, watchType, denial);
            verify(retryHandler).shouldRetry();
            if (shouldRetry) {
                verify(retryHandler).tryScheduleRetry(any(Runnable.class));
            } else {
                verify(retryHandler, never()).tryScheduleRetry(any(Runnable.class));
            }
        } finally {
            context.close();
        }
    }

    @ParameterizedTest
    @MethodSource("permissionDeniedRetryFailureCases")
    @SuppressWarnings("rawtypes")
    void repeatedDenialRetryFailureDoesNotNotifyAgain(WatchType watchType, boolean shouldRetry) {
        Watcher watcher = mock(Watcher.class);
        RetryHandler retryHandler = mock(RetryHandler.class);
        when(retryHandler.shouldRetry()).thenReturn(true, shouldRetry);
        when(retryHandler.tryScheduleRetry(any(Runnable.class))).thenReturn(true, false);
        Throwable denial = Status.PERMISSION_DENIED.asRuntimeException();

        Context.CancellableContext context = Context.current().withCancellation();
        try {
            StreamObserver<?> observer = newStreamObserver(watchType, watcher, retryHandler, context);
            deliverUpdate(watchType, observer);
            observer.onError(denial);
            observer.onError(Status.PERMISSION_DENIED.asRuntimeException());

            assertWatcherError(watcher, watchType, denial);
            verify(retryHandler, times(2)).shouldRetry();
            verify(retryHandler, times(shouldRetry ? 2 : 1)).tryScheduleRetry(any(Runnable.class));
        } finally {
            context.close();
        }
    }

    @ParameterizedTest
    @MethodSource("permissionDeniedRetryFailureCases")
    @SuppressWarnings("rawtypes")
    void distinctRetryFailureAfterReportedDenialNotifiesWatcher(WatchType watchType, boolean shouldRetry) {
        Watcher watcher = mock(Watcher.class);
        RetryHandler retryHandler = mock(RetryHandler.class);
        when(retryHandler.shouldRetry()).thenReturn(true, shouldRetry);
        when(retryHandler.tryScheduleRetry(any(Runnable.class))).thenReturn(true, false);
        Throwable denial = Status.PERMISSION_DENIED.asRuntimeException();
        Throwable retryError = Status.UNAVAILABLE.asRuntimeException();

        Context.CancellableContext context = Context.current().withCancellation();
        try {
            StreamObserver<?> observer = newStreamObserver(watchType, watcher, retryHandler, context);
            deliverUpdate(watchType, observer);
            observer.onError(denial);
            observer.onError(retryError);

            ArgumentCaptor<Throwable> errors = ArgumentCaptor.forClass(Throwable.class);
            verify(watcher, times(2)).onError(errors.capture());
            assertInstanceOf(watchType.errorType, errors.getAllValues().get(0));
            assertSame(denial, errors.getAllValues().get(0).getCause());
            assertInstanceOf(watchType.errorType, errors.getAllValues().get(1));
            assertSame(retryError, errors.getAllValues().get(1).getCause());
            verify(retryHandler, times(2)).shouldRetry();
            verify(retryHandler, times(shouldRetry ? 2 : 1)).tryScheduleRetry(any(Runnable.class));
        } finally {
            context.close();
        }
    }

    @ParameterizedTest
    @EnumSource(WatchType.class)
    @SuppressWarnings("rawtypes")
    void throwingPermissionDeniedCallbackPreventsRetry(WatchType watchType) {
        Watcher watcher = mock(Watcher.class);
        RetryHandler retryHandler = mock(RetryHandler.class);
        RuntimeException callbackError = new RuntimeException("watcher stopped");
        doThrow(callbackError).when(watcher).onError(any(Throwable.class));

        Context.CancellableContext context = Context.current().withCancellation();
        try {
            StreamObserver<?> observer = newStreamObserver(watchType, watcher, retryHandler, context);
            deliverUpdate(watchType, observer);

            assertSame(callbackError, assertThrows(RuntimeException.class,
                    () -> observer.onError(Status.PERMISSION_DENIED.asRuntimeException())));
            verify(retryHandler, never()).shouldRetry();
            verify(retryHandler, never()).tryScheduleRetry(any(Runnable.class));
        } finally {
            context.close();
        }
    }

    @ParameterizedTest
    @EnumSource(WatchType.class)
    @SuppressWarnings("rawtypes")
    void permissionDeniedSchedulesWatchRetry(WatchType watchType) {
        Watcher watcher = mock(Watcher.class);
        RetryHandler retryHandler = mock(RetryHandler.class);
        when(retryHandler.shouldRetry()).thenReturn(true);
        when(retryHandler.tryScheduleRetry(any(Runnable.class))).thenReturn(true);

        Context.CancellableContext cancellableContext = Context.current().withCancellation();
        try {
            StreamObserver<?> streamObserver =
                    newStreamObserver(watchType, watcher, retryHandler, cancellableContext);
            streamObserver.onError(Status.PERMISSION_DENIED.asRuntimeException());

            verify(retryHandler).shouldRetry();
            verify(retryHandler).tryScheduleRetry(any(Runnable.class));
            verify(watcher, never()).onError(any(Throwable.class));
        } finally {
            cancellableContext.close();
        }
    }

    @ParameterizedTest
    @MethodSource("nonRetryableStatusCases")
    @SuppressWarnings("rawtypes")
    void nonRetryableStatusStopsWatch(WatchType watchType, Status.Code statusCode) {
        Watcher watcher = mock(Watcher.class);
        RetryHandler retryHandler = mock(RetryHandler.class);

        Context.CancellableContext cancellableContext = Context.current().withCancellation();
        try {
            StreamObserver<?> streamObserver =
                    newStreamObserver(watchType, watcher, retryHandler, cancellableContext);
            streamObserver.onError(Status.fromCode(statusCode).asRuntimeException());

            ArgumentCaptor<Throwable> errorCaptor = ArgumentCaptor.forClass(Throwable.class);
            verify(watcher).onError(errorCaptor.capture());
            assertInstanceOf(watchType.errorType, errorCaptor.getValue());
            verify(retryHandler, never()).shouldRetry();
            verify(retryHandler, never()).tryScheduleRetry(any(Runnable.class));
        } finally {
            cancellableContext.close();
        }
    }

    @ParameterizedTest
    @EnumSource(WatchType.class)
    @SuppressWarnings("rawtypes")
    void exhaustedRetriesReportTypedError(WatchType watchType) {
        Watcher watcher = mock(Watcher.class);
        RetryHandler retryHandler = mock(RetryHandler.class);
        when(retryHandler.shouldRetry()).thenReturn(false);
        Throwable retryError = Status.UNAVAILABLE.asRuntimeException();

        Context.CancellableContext cancellableContext = Context.current().withCancellation();
        try {
            StreamObserver<?> streamObserver =
                    newStreamObserver(watchType, watcher, retryHandler, cancellableContext);
            streamObserver.onError(retryError);

            assertWatcherError(watcher, watchType, retryError);
            verify(retryHandler).shouldRetry();
            verify(retryHandler, never()).tryScheduleRetry(any(Runnable.class));
        } finally {
            cancellableContext.close();
        }
    }

    @ParameterizedTest
    @EnumSource(WatchType.class)
    @SuppressWarnings("rawtypes")
    void rejectedRetrySchedulingReportsTypedError(WatchType watchType) {
        Watcher watcher = mock(Watcher.class);
        RetryHandler retryHandler = mock(RetryHandler.class);
        when(retryHandler.shouldRetry()).thenReturn(true);
        when(retryHandler.tryScheduleRetry(any(Runnable.class))).thenReturn(false);
        Throwable retryError = Status.UNAVAILABLE.asRuntimeException();

        Context.CancellableContext cancellableContext = Context.current().withCancellation();
        try {
            StreamObserver<?> streamObserver =
                    newStreamObserver(watchType, watcher, retryHandler, cancellableContext);
            streamObserver.onError(retryError);

            assertWatcherError(watcher, watchType, retryError);
            verify(retryHandler).shouldRetry();
            verify(retryHandler).tryScheduleRetry(any(Runnable.class));
        } finally {
            cancellableContext.close();
        }
    }

    private static Stream<Arguments> permissionDeniedRetryFailureCases() {
        return Stream.of(WatchType.values())
                .flatMap(watchType -> Stream.of(false, true)
                        .map(shouldRetry -> Arguments.of(watchType, shouldRetry)));
    }

    @SuppressWarnings("unchecked")
    private void deliverUpdate(WatchType watchType, StreamObserver<?> observer) {
        FakeWorkloadApi service = new FakeWorkloadApi();
        switch (watchType) {
            case X509_CONTEXT:
                service.fetchX509SVID(Workload.X509SVIDRequest.getDefaultInstance(),
                        withoutCompletion((StreamObserver<Workload.X509SVIDResponse>) observer));
                break;
            case X509_BUNDLES:
                service.fetchX509Bundles(Workload.X509BundlesRequest.getDefaultInstance(),
                        withoutCompletion((StreamObserver<Workload.X509BundlesResponse>) observer));
                break;
            case JWT_BUNDLES:
                service.fetchJWTBundles(Workload.JWTBundlesRequest.getDefaultInstance(),
                        withoutCompletion((StreamObserver<Workload.JWTBundlesResponse>) observer));
                break;
            default:
                throw new IllegalArgumentException("Unsupported watch type: " + watchType);
        }
    }

    private static <T> StreamObserver<T> withoutCompletion(StreamObserver<T> observer) {
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
                // Leave the watch open for the next update or error.
            }
        };
    }

    private static Stream<Arguments> nonRetryableStatusCases() {
        return Stream.of(WatchType.values())
                .flatMap(watchType -> Stream.of(
                                Status.Code.INVALID_ARGUMENT,
                                Status.Code.CANCELLED,
                                Status.Code.UNAUTHENTICATED,
                                Status.Code.UNIMPLEMENTED,
                                Status.Code.FAILED_PRECONDITION)
                        .map(statusCode -> Arguments.of(watchType, statusCode)));
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private StreamObserver<?> newStreamObserver(
            WatchType watchType,
            Watcher watcher,
            RetryHandler retryHandler,
            Context.CancellableContext cancellableContext) {
        switch (watchType) {
            case X509_CONTEXT:
                return StreamObservers.getX509ContextStreamObserver(
                        (Watcher<X509Context>) watcher,
                        retryHandler,
                        cancellableContext,
                        null);
            case X509_BUNDLES:
                return StreamObservers.getX509BundlesStreamObserver(
                        (Watcher<X509BundleSet>) watcher,
                        retryHandler,
                        cancellableContext,
                        null);
            case JWT_BUNDLES:
                return StreamObservers.getJwtBundleStreamObserver(
                        (Watcher<JwtBundleSet>) watcher,
                        retryHandler,
                        cancellableContext,
                        null);
            default:
                throw new IllegalArgumentException("Unsupported watch type: " + watchType);
        }
    }

    @SuppressWarnings("rawtypes")
    private void assertWatcherError(Watcher watcher, WatchType watchType, Throwable cause) {
        ArgumentCaptor<Throwable> errorCaptor = ArgumentCaptor.forClass(Throwable.class);
        verify(watcher).onError(errorCaptor.capture());
        Throwable watcherError = errorCaptor.getValue();
        assertInstanceOf(watchType.errorType, watcherError);
        assertSame(cause, watcherError.getCause());
    }

    private enum WatchType {
        X509_CONTEXT(X509ContextException.class),
        X509_BUNDLES(X509BundleException.class),
        JWT_BUNDLES(JwtBundleException.class);

        private final Class<? extends Throwable> errorType;

        WatchType(Class<? extends Throwable> errorType) {
            this.errorType = errorType;
        }
    }
}
