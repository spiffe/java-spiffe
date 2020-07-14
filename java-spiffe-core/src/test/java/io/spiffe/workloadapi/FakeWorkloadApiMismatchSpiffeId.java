package io.spiffe.workloadapi;

import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import io.spiffe.workloadapi.grpc.SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIImplBase;
import io.spiffe.workloadapi.grpc.Workload;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

class FakeWorkloadApiMismatchSpiffeId extends SpiffeWorkloadAPIImplBase {

    final String privateKey = "testdata/workloadapi/svid.key.der";
    final String svid = "testdata/workloadapi/svid.der";
    final String x509Bundle = "testdata/workloadapi/bundle.der";
    final String jwtBundle = "testdata/workloadapi/bundle.json";

    @Override
    public void fetchX509SVID(Workload.X509SVIDRequest request, StreamObserver<Workload.X509SVIDResponse> responseObserver) {
        try {
            Path pathCert = Paths.get(toUri(svid));
            byte[] svidBytes = Files.readAllBytes(pathCert);
            ByteString svidByteString = ByteString.copyFrom(svidBytes);

            Path pathKey = Paths.get(toUri(privateKey));
            byte[] keyBytes = Files.readAllBytes(pathKey);
            ByteString keyByteString = ByteString.copyFrom(keyBytes);

            Path pathBundle = Paths.get(toUri(x509Bundle));
            byte[] bundleBytes = Files.readAllBytes(pathBundle);
            ByteString bundleByteString = ByteString.copyFrom(bundleBytes);

            Workload.X509SVID svid = Workload.X509SVID
                    .newBuilder()
                    .setSpiffeId("spiffe://wrong/domain/workload-server")
                    .setX509Svid(svidByteString)
                    .setX509SvidKey(keyByteString)
                    .setBundle(bundleByteString)
                    .build();

            Workload.X509SVIDResponse response = Workload.X509SVIDResponse
                    .newBuilder()
                    .addSvids(svid)
                    .build();

            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (URISyntaxException | IOException e) {
            throw new Error("Failed FakeSpiffeWorkloadApiService.fetchX509SVID", e);
        }
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

    private URI toUri(String path) throws URISyntaxException {
        return Thread.currentThread().getContextClassLoader().getResource(path).toURI();
    }
}

