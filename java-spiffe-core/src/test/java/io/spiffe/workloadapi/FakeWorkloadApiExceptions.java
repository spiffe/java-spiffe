package io.spiffe.workloadapi;

import io.grpc.Status;
import io.grpc.StatusException;
import io.grpc.stub.StreamObserver;
import io.spiffe.workloadapi.grpc.SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIImplBase;
import io.spiffe.workloadapi.grpc.Workload;

class FakeWorkloadApiExceptions extends SpiffeWorkloadAPIImplBase {

    private final StatusException exception;

    FakeWorkloadApiExceptions(Status errorStatus) {
        exception = new StatusException(errorStatus);
    }


    @Override
    public void fetchX509SVID(Workload.X509SVIDRequest request, StreamObserver<Workload.X509SVIDResponse> responseObserver) {
        responseObserver.onError(exception);
    }

    @Override
    public void fetchJWTSVID(Workload.JWTSVIDRequest request, StreamObserver<Workload.JWTSVIDResponse> responseObserver) {
        responseObserver.onError(exception);
    }

    @Override
    public void fetchJWTBundles(Workload.JWTBundlesRequest request, StreamObserver<Workload.JWTBundlesResponse> responseObserver) {
        responseObserver.onError(exception);
    }

    @Override
    public void validateJWTSVID(Workload.ValidateJWTSVIDRequest request, StreamObserver<Workload.ValidateJWTSVIDResponse> responseObserver) {
        responseObserver.onError(exception);
    }
}

