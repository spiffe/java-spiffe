package spiffe.workloadapi;

import com.google.protobuf.ByteString;
import com.google.protobuf.ProtocolStringList;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import com.nimbusds.jose.jwk.Curve;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;
import org.junit.platform.commons.util.StringUtils;
import spiffe.exception.JwtSvidException;
import spiffe.svid.jwtsvid.JwtSvid;
import spiffe.utils.TestUtils;
import spiffe.workloadapi.internal.SpiffeWorkloadAPIGrpc;
import spiffe.workloadapi.internal.Workload;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.util.*;

class FakeWorkloadApi extends SpiffeWorkloadAPIGrpc.SpiffeWorkloadAPIImplBase {

    final String privateKey = "testdata/workloadapi/svid.key";
    final String svid = "testdata/workloadapi/svid.pem";
    final String x509Bundle = "testdata/workloadapi/bundle.pem";
    final String jwtBundle = "testdata/workloadapi/bundle.json";


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


    @Override
    public void fetchJWTSVID(Workload.JWTSVIDRequest request, StreamObserver<Workload.JWTSVIDResponse> responseObserver) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", request.getSpiffeId());
        claims.put("aud", getAudienceList(request.getAudienceList()));
        Date expiration = new Date(System.currentTimeMillis() + 3600000);
        claims.put("exp", expiration);

        KeyPair keyPair = TestUtils.generateECKeyPair(Curve.P_521);

        String token = TestUtils.generateToken(claims, keyPair, "authority1");

        Workload.JWTSVID jwtsvid = Workload.JWTSVID
                .newBuilder()
                .setSpiffeId("spiffe://example.org/workload-server")
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
            jwtSvid = JwtSvid.parseInsecure(token, Collections.singletonList(audience));
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

    private URI toUri(String path) throws URISyntaxException {
        return getClass().getClassLoader().getResource(path).toURI();
    }
}

