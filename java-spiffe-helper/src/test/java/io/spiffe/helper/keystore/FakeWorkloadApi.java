package io.spiffe.helper.keystore;

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

class FakeWorkloadApi extends SpiffeWorkloadAPIImplBase {

    final String privateKey = "testdata/svid.key";
    final String svid = "testdata/svid.pem";
    final String x509Bundle = "testdata/bundle.pem";


    // Loads cert, bundle and key from files and generates a X509SVIDResponse.
    @Override
    public void fetchX509SVID(Workload.X509SVIDRequest request, StreamObserver<Workload.X509SVIDResponse> responseObserver) {
        try {
            Path pathCert = Paths.get(toUri(svid));
            byte[] svidBytes = Files.readAllBytes(pathCert);

            Path pathKey = Paths.get(toUri(privateKey));
            byte[] keyBytes = Files.readAllBytes(pathKey);

            Path pathBundle = Paths.get(toUri(x509Bundle));
            byte[] bundleBytes = Files.readAllBytes(pathBundle);

            Workload.X509SVID svid = Workload.X509SVID
                    .newBuilder()
                    .setSpiffeId("spiffe://example.org/workload-server")
                    .setX509Svid(ByteString.copyFrom(svidBytes))
                    .setX509SvidKey(ByteString.copyFrom(keyBytes))
                    .setBundle(ByteString.copyFrom(bundleBytes))
                    .build();
            Workload.X509SVIDResponse response = Workload.X509SVIDResponse.newBuilder().addSvids(svid).build();
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (URISyntaxException | IOException e) {
            throw new Error("Failed FakeSpiffeWorkloadApiService.fetchX509SVID", e);
        }
    }

    private URI toUri(String path) throws URISyntaxException {
        return Thread.currentThread().getContextClassLoader().getResource(path).toURI();
    }
}

