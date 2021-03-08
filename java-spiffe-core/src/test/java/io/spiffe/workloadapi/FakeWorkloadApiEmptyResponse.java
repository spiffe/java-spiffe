package io.spiffe.workloadapi;

import io.grpc.stub.StreamObserver;
import io.spiffe.workloadapi.grpc.SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIImplBase;
import io.spiffe.workloadapi.grpc.Workload;

class FakeWorkloadApiEmptyResponse extends SpiffeWorkloadAPIImplBase {

    @Override
    public void fetchX509SVID(Workload.X509SVIDRequest request, StreamObserver<Workload.X509SVIDResponse> responseObserver) {
        responseObserver.onNext(Workload.X509SVIDResponse.newBuilder().build());
        responseObserver.onCompleted();
    }

    @Override
    public void fetchX509Bundles(Workload.X509BundlesRequest request, StreamObserver<Workload.X509BundlesResponse> responseObserver) {
        responseObserver.onNext(Workload.X509BundlesResponse.newBuilder().build());
        responseObserver.onCompleted();
    }

    @Override
    public void fetchJWTSVID(Workload.JWTSVIDRequest request, StreamObserver<Workload.JWTSVIDResponse> responseObserver) {
        responseObserver.onNext(Workload.JWTSVIDResponse.newBuilder().build());
        responseObserver.onCompleted();
    }

    @Override
    public void fetchJWTBundles(Workload.JWTBundlesRequest request, StreamObserver<Workload.JWTBundlesResponse> responseObserver) {
        responseObserver.onNext(Workload.JWTBundlesResponse.newBuilder().build());
        responseObserver.onCompleted();
    }

    @Override
    public void validateJWTSVID(Workload.ValidateJWTSVIDRequest request, StreamObserver<Workload.ValidateJWTSVIDResponse> responseObserver) {
        responseObserver.onNext(Workload.ValidateJWTSVIDResponse.newBuilder().build());
        responseObserver.onCompleted();
    }
}

