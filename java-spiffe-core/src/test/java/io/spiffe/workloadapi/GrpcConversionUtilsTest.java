package io.spiffe.workloadapi;

import com.google.protobuf.ByteString;
import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.bundle.x509bundle.X509BundleSet;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.exception.JwtBundleException;
import io.spiffe.exception.X509BundleException;
import io.spiffe.exception.X509ContextException;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.svid.x509svid.X509Svid;
import io.spiffe.workloadapi.grpc.Workload;
import org.junit.jupiter.api.Test;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import static io.spiffe.utils.TestUtils.toUri;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

class GrpcConversionUtilsTest {

    final String x509Bundle = "testdata/workloadapi/bundle.der";
    final String federatedBundle = "testdata/workloadapi/federated-bundle.pem";

    @Test
    void test_toX509Context_emptyResponse() {
        Iterator<Workload.X509SVIDResponse> iterator = Collections.emptyIterator();
        try {
            GrpcConversionUtils.toX509Context(iterator);
        } catch (X509ContextException e) {
            assertEquals("X.509 Context response from the Workload API is empty", e.getMessage());
        }
    }

    @Test
    void test_toJwtBundleSet_emtpyResponse() {
        Iterator<Workload.JWTBundlesResponse> iterator = Collections.emptyIterator();
        try {
            GrpcConversionUtils.toJwtBundleSet(iterator);
        } catch (JwtBundleException e) {
            assertEquals("JWT Bundle response from the Workload API is empty", e.getMessage());
        }
    }

    @Test
    void test_parseX509Bundle_corruptedBytes() {
        try {
            GrpcConversionUtils.parseX509Bundle(TrustDomain.parse("example.org"), "corrupted".getBytes());
        } catch (X509ContextException e) {
            assertEquals("X.509 Bundles could not be processed", e.getMessage());
        }
    }

    @Test
    void test_toX509BundleSet_from_X509BundlesResponse() throws URISyntaxException, IOException {
        Workload.X509BundlesResponse response = createX509BundlesResponse();

        try {
            X509BundleSet x509BundleSet = GrpcConversionUtils.toX509BundleSet(response);
            X509Bundle bundle1 = x509BundleSet.getBundleForTrustDomain(TrustDomain.parse("example.org"));
            X509Bundle bundle2 = x509BundleSet.getBundleForTrustDomain(TrustDomain.parse("domain.test"));
            assertEquals(1, bundle1.getX509Authorities().size());
            assertEquals(1, bundle2.getX509Authorities().size());
        } catch (X509BundleException | BundleNotFoundException e) {
            fail();
        }
    }

    @Test
    void test_toX509BundleSet_from_X509BundlesResponseIterator() throws URISyntaxException, IOException {
        Workload.X509BundlesResponse response = createX509BundlesResponse();
        final Iterator<Workload.X509BundlesResponse> iterator = Collections.singleton(response).iterator();

        try {
            X509BundleSet x509BundleSet = GrpcConversionUtils.toX509BundleSet(iterator);
            X509Bundle bundle1 = x509BundleSet.getBundleForTrustDomain(TrustDomain.parse("example.org"));
            X509Bundle bundle2 = x509BundleSet.getBundleForTrustDomain(TrustDomain.parse("domain.test"));
            assertEquals(1, bundle1.getX509Authorities().size());
            assertEquals(1, bundle2.getX509Authorities().size());
        } catch (X509BundleException | BundleNotFoundException e) {
            fail();
        }
    }

    @Test
    void test_toX509BundleSet_fromEmptyResponse() {
        Workload.X509BundlesResponse response = Workload.X509BundlesResponse.newBuilder().build();
        try {
            GrpcConversionUtils.toX509BundleSet(response);
            fail();
        } catch (X509BundleException e) {
            assertEquals("X.509 Bundle response from the Workload API is empty", e.getMessage());
        }

    }

    @Test
    void test_toX509BundleSet_fromEmptyIterator() {
        final Iterator<Workload.X509BundlesResponse> iterator = Collections.emptyListIterator();
        try {
            GrpcConversionUtils.toX509BundleSet(iterator);
            fail();
        } catch (X509BundleException e) {
            assertEquals("X.509 Bundle response from the Workload API is empty", e.getMessage());
        }

    }

    private Workload.X509BundlesResponse createX509BundlesResponse() throws URISyntaxException, IOException {
        Path pathBundle = Paths.get(toUri(x509Bundle));
        byte[] bundleBytes = Files.readAllBytes(pathBundle);
        ByteString bundleByteString = ByteString.copyFrom(bundleBytes);

        Path pathFederateBundle = Paths.get(toUri(federatedBundle));
        byte[] federatedBundleBytes = Files.readAllBytes(pathFederateBundle);
        ByteString federatedByteString = ByteString.copyFrom(federatedBundleBytes);

        return Workload.X509BundlesResponse
                .newBuilder()
                .putBundles(TrustDomain.parse("example.org").getName(), bundleByteString)
                .putBundles(TrustDomain.parse("domain.test").getName(), federatedByteString)
                .build();
    }

    @Test
    void getListOfX509Svid_dedupesOnlyNonEmptyHints() throws Exception {

        ByteString certA = loadTestResource("testdata/certs/leaf-a.crt.der");
        ByteString keyA  = loadTestResource("testdata/certs/leaf-a.key.der");

        ByteString certB = loadTestResource("testdata/certs/leaf-b.crt.der");
        ByteString keyB  = loadTestResource("testdata/certs/leaf-b.key.der");

        ByteString certC = loadTestResource("testdata/certs/leaf-c.crt.der");
        ByteString keyC  = loadTestResource("testdata/certs/leaf-c.key.der");

        ByteString certD = loadTestResource("testdata/certs/leaf-d.crt.der");
        ByteString keyD  = loadTestResource("testdata/certs/leaf-d.key.der");

        ByteString certE = loadTestResource("testdata/certs/leaf-e.crt.der");
        ByteString keyE  = loadTestResource("testdata/certs/leaf-e.key.der");

        Workload.X509SVID svidA = Workload.X509SVID.newBuilder()
                .setHint("")
                .setSpiffeId("spiffe://test/a")
                .setX509Svid(certA)
                .setX509SvidKey(keyA)
                .build();

        Workload.X509SVID svidB = Workload.X509SVID.newBuilder()
                .setHint("")
                .setSpiffeId("spiffe://test/b")
                .setX509Svid(certB)
                .setX509SvidKey(keyB)
                .build();

        Workload.X509SVID svidC = Workload.X509SVID.newBuilder()
                .setHint("hintX")
                .setSpiffeId("spiffe://test/c")
                .setX509Svid(certC)
                .setX509SvidKey(keyC)
                .build();

        Workload.X509SVID svidD = Workload.X509SVID.newBuilder()
                .setHint("hintX")
                .setSpiffeId("spiffe://test/d")
                .setX509Svid(certD)
                .setX509SvidKey(keyD)
                .build();

        Workload.X509SVID svidE = Workload.X509SVID.newBuilder()
                .setHint("hintY")
                .setSpiffeId("spiffe://test/e")
                .setX509Svid(certE)
                .setX509SvidKey(keyE)
                .build();

        Workload.X509SVIDResponse resp = Workload.X509SVIDResponse.newBuilder()
                .addSvids(svidA)
                .addSvids(svidB)
                .addSvids(svidC)
                .addSvids(svidD)
                .addSvids(svidE)
                .build();

        // Act
        List<X509Svid> out = GrpcConversionUtils.getListOfX509Svid(resp);

        // Assert: B must NOT be removed; D must be removed; order preserved
        assertEquals(4, out.size());
        assertEquals("spiffe://test/a", out.get(0).getSpiffeId().toString());
        assertEquals("spiffe://test/b", out.get(1).getSpiffeId().toString());
        assertEquals("spiffe://test/c", out.get(2).getSpiffeId().toString());
        assertEquals("spiffe://test/e", out.get(3).getSpiffeId().toString());

    }

    private static ByteString loadTestResource(String resourcePath) throws IOException {
        try (InputStream in = GrpcConversionUtilsTest.class.getResourceAsStream("/" + resourcePath)) {
            if (in == null) {
                throw new FileNotFoundException("Resource not found on classpath: " + resourcePath);
            }
            return ByteString.copyFrom(in.readAllBytes());
        }
    }
}