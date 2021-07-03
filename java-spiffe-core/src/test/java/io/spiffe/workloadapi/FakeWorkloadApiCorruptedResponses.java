package io.spiffe.workloadapi;

import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.workloadapi.grpc.SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIImplBase;
import io.spiffe.workloadapi.grpc.Workload;
import org.junit.platform.commons.util.StringUtils;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static io.spiffe.utils.TestUtils.toUri;

class FakeWorkloadApiCorruptedResponses extends SpiffeWorkloadAPIImplBase {

    final String corrupted = "testdata/workloadapi/corrupted";

    @Override
    public void fetchX509SVID(Workload.X509SVIDRequest request, StreamObserver<Workload.X509SVIDResponse> responseObserver) {
        try {

            Path pathToCorrupted = Paths.get(toUri(corrupted));
            byte[] corruptedBytes = Files.readAllBytes(pathToCorrupted);
            ByteString corruptedByteString = ByteString.copyFrom(corruptedBytes);

            Workload.X509SVID svid = Workload.X509SVID
                    .newBuilder()
                    .setSpiffeId("spiffe://example.org/workload-server")
                    .setX509Svid(corruptedByteString)
                    .setX509SvidKey(corruptedByteString)
                    .setBundle(corruptedByteString)
                    .build();

            Workload.X509SVIDResponse response = Workload.X509SVIDResponse
                    .newBuilder()
                    .addSvids(svid)
                    .putFederatedBundles(TrustDomain.parse("domain.test").getName(), corruptedByteString)
                    .build();

            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (URISyntaxException | IOException e) {
            throw new Error("Failed FakeSpiffeWorkloadApiService.fetchX509SVID", e);
        }
    }

    @Override
    public void fetchX509Bundles(Workload.X509BundlesRequest request, StreamObserver<Workload.X509BundlesResponse> responseObserver) {
        Path pathBundle = null;
        try {
            pathBundle = Paths.get(toUri(corrupted));
            byte[] bundleBytes = Files.readAllBytes(pathBundle);
            ByteString corruptedByteString = ByteString.copyFrom(bundleBytes);

            Workload.X509BundlesResponse response = Workload.X509BundlesResponse
                    .newBuilder()
                    .putBundles("example.org", corruptedByteString)
                    .build();

            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (URISyntaxException | IOException e) {
            throw new Error("Failed FakeSpiffeWorkloadApiService.fetchX509Bundles", e);
        }
    }

    @Override
    public void fetchJWTSVID(Workload.JWTSVIDRequest request, StreamObserver<Workload.JWTSVIDResponse> responseObserver) {
        String spiffeId = request.getSpiffeId();
        if (StringUtils.isBlank(spiffeId)) {
            spiffeId = "spiffe://example.org/workload-server";
        }
        Workload.JWTSVID jwtsvid = Workload.JWTSVID
                .newBuilder()
                .setSpiffeId(spiffeId)
                .setSvid("corrupted token")
                .build();
        Workload.JWTSVIDResponse response = Workload.JWTSVIDResponse.newBuilder().addSvids(jwtsvid).build();
        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void fetchJWTBundles(Workload.JWTBundlesRequest request, StreamObserver<Workload.JWTBundlesResponse> responseObserver) {
        Path pathBundle = null;
        try {
            pathBundle = Paths.get(toUri(corrupted));
            byte[] bundleBytes = Files.readAllBytes(pathBundle);
            ByteString corruptedByteString = ByteString.copyFrom(bundleBytes);

            Workload.JWTBundlesResponse response = Workload.JWTBundlesResponse
                    .newBuilder()
                    .putBundles("example.org", corruptedByteString)
                    .build();

            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (URISyntaxException | IOException e) {
            throw new Error("Failed FakeSpiffeWorkloadApiService.fetchJWTBundles", e);
        }
    }

    @Override
    public void validateJWTSVID(Workload.ValidateJWTSVIDRequest request, StreamObserver<Workload.ValidateJWTSVIDResponse> responseObserver) {
        responseObserver.onNext(Workload.ValidateJWTSVIDResponse.newBuilder().build());
        responseObserver.onCompleted();
    }
}

