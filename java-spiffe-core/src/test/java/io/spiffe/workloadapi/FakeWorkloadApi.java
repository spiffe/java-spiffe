package io.spiffe.workloadapi;

import com.google.protobuf.ByteString;
import com.google.protobuf.ProtocolStringList;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import com.nimbusds.jose.jwk.Curve;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;
import io.spiffe.exception.JwtSvidException;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.svid.jwtsvid.JwtSvid;
import io.spiffe.utils.TestUtils;
import io.spiffe.workloadapi.grpc.SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIImplBase;
import io.spiffe.workloadapi.grpc.Workload;
import org.junit.platform.commons.util.StringUtils;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.spiffe.utils.TestUtils.toUri;

class FakeWorkloadApi extends SpiffeWorkloadAPIImplBase {

    final String privateKey = "testdata/workloadapi/svid.key.der";
    final String svid = "testdata/workloadapi/svid.der";
    final String x509Bundle = "testdata/workloadapi/bundle.der";
    final String federatedBundle = "testdata/workloadapi/federated-bundle.pem";
    final String jwtBundle = "testdata/workloadapi/bundle.json";


    // Loads cert, bundle and key from files and generates an X509SVIDResponse.
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

            Path pathFederateBundle = Paths.get(toUri(federatedBundle));
            byte[] federatedBundleBytes = Files.readAllBytes(pathFederateBundle);
            ByteString federatedByteString = ByteString.copyFrom(federatedBundleBytes);

            Workload.X509SVID svid = Workload.X509SVID
                    .newBuilder()
                    .setSpiffeId("spiffe://example.org/workload-server")
                    .setX509Svid(svidByteString)
                    .setX509SvidKey(keyByteString)
                    .setBundle(bundleByteString)
                    .build();

            Workload.X509SVIDResponse response = Workload.X509SVIDResponse
                    .newBuilder()
                    .addSvids(svid)
                    .putFederatedBundles(TrustDomain.parse("domain.test").getName(), federatedByteString)
                    .build();

            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (URISyntaxException | IOException e) {
            throw new Error("Failed FakeSpiffeWorkloadApiService.fetchX509SVID", e);
        }
    }

    @Override
    public void fetchX509Bundles(Workload.X509BundlesRequest request, StreamObserver<Workload.X509BundlesResponse> responseObserver) {
        try {
            Path pathBundle = Paths.get(toUri(x509Bundle));
            byte[] bundleBytes = Files.readAllBytes(pathBundle);
            ByteString bundleByteString = ByteString.copyFrom(bundleBytes);

            Path pathFederateBundle = Paths.get(toUri(federatedBundle));
            byte[] federatedBundleBytes = Files.readAllBytes(pathFederateBundle);
            ByteString federatedByteString = ByteString.copyFrom(federatedBundleBytes);

            Workload.X509BundlesResponse response = Workload.X509BundlesResponse
                    .newBuilder()
                    .putBundles(TrustDomain.parse("example.org").getName(), bundleByteString)
                    .putBundles(TrustDomain.parse("domain.test").getName(), federatedByteString)
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
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", spiffeId);
        claims.put("aud", getAudienceList(request.getAudienceList()));
        Date expiration = new Date(System.currentTimeMillis() + 3600000);
        claims.put("exp", expiration);

        KeyPair keyPair = TestUtils.generateECKeyPair(Curve.P_521);

        String token = TestUtils.generateToken(claims, keyPair, "authority1");

        Workload.JWTSVID jwtsvid = Workload.JWTSVID
                .newBuilder()
                .setSpiffeId(spiffeId)
                .setSvid(token)
                .build();
        Workload.JWTSVIDResponse response = Workload.JWTSVIDResponse.newBuilder().addSvids(jwtsvid).build();
        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    List<String> getAudienceList(ProtocolStringList audienceList) {
        List<String> result = new ArrayList<>();
        for (ByteString str : audienceList.asByteStringList()) {
            result.add(str.toStringUtf8());
        }
        return result;
    }

    @Override
    public void fetchJWTBundles(Workload.JWTBundlesRequest request, StreamObserver<Workload.JWTBundlesResponse> responseObserver) {
        Path pathBundle = null;
        try {
            pathBundle = Paths.get(toUri(jwtBundle));
            byte[] bundleBytes = Files.readAllBytes(pathBundle);

            Workload.JWTBundlesResponse response = Workload.JWTBundlesResponse
                    .newBuilder()
                    .putBundles("example.org", ByteString.copyFrom(bundleBytes))
                    .build();

            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (URISyntaxException | IOException e) {
            throw new Error("Failed FakeSpiffeWorkloadApiService.fetchJWTBundles", e);
        }
    }

    @Override
    public void validateJWTSVID(Workload.ValidateJWTSVIDRequest request, StreamObserver<Workload.ValidateJWTSVIDResponse> responseObserver) {
        String audience = request.getAudience();
        if (StringUtils.isBlank(audience)) {
            responseObserver.onError(new StatusRuntimeException(Status.INVALID_ARGUMENT.withDescription("audience must be specified")));
        }

        String token = request.getSvid();
        if (StringUtils.isBlank(token)) {
            responseObserver.onError(new StatusRuntimeException(Status.INVALID_ARGUMENT.withDescription("svid must be specified")));
        }

        JwtSvid jwtSvid = null;
        try {
            jwtSvid = JwtSvid.parseInsecure(token, Collections.singleton(audience));
        } catch (JwtSvidException e) {
            responseObserver.onError(new StatusRuntimeException(Status.INVALID_ARGUMENT.withDescription(e.getMessage())));
        }

        Struct structClaims = getClaimsStruct(jwtSvid.getClaims());

        Workload.ValidateJWTSVIDResponse response = Workload.ValidateJWTSVIDResponse
                .newBuilder()
                .setSpiffeId(jwtSvid.getSpiffeId().toString())
                .setClaims(structClaims)
                .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    private Struct getClaimsStruct(Map<String, Object> claims) {
        Map<String, Value> valueMap = new HashMap<>();
        Value sub = Value.newBuilder().setStringValue((String) claims.get("sub")).build();

        Date expirationDate = (Date) claims.get("exp");
        String time = String.valueOf(expirationDate.getTime());
        Value exp = Value.newBuilder().setStringValue(time).build();

        List<String> audience = (List<String>) claims.get("aud");
        Value aud = Value.newBuilder().setStringValue(audience.get(0)).build();

        valueMap.put("sub", sub);
        valueMap.put("exp", exp);
        valueMap.put("aud", aud);

        return Struct.newBuilder().putAllFields(valueMap).build();
    }

}

