package io.spiffe.bundle.x509bundle;

import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.exception.X509BundleException;
import io.spiffe.internal.DummyX509Certificate;
import io.spiffe.spiffeid.TrustDomain;
import lombok.Builder;
import lombok.Value;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.platform.commons.util.StringUtils;

import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.stream.Stream;

import static io.spiffe.utils.TestUtils.toUri;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class X509BundleTest {

    @Test
    void TestNewBundle() {
        X509Bundle x509Bundle = new X509Bundle(TrustDomain.parse("example.org"));
        assertEquals(0, x509Bundle.getX509Authorities().size());
        assertEquals(TrustDomain.parse("example.org"), x509Bundle.getTrustDomain());
    }

    @Test
    void testNewBundle_nullTrustDomain_throwsNullPointerException() {
        try {
            new X509Bundle(null );
            fail("should have thrown exception");
        } catch (NullPointerException e) {
            assertEquals("trustDomain is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testNewBundleWithAuthorities_nullTrustDomain_throwsNullPointerException() {
        try {
            new X509Bundle(null, new HashSet<>());
            fail("should have thrown exception");
        } catch (NullPointerException e) {
            assertEquals("trustDomain is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testNewBundleAuthorities_nullAuthorities_throwsNullPointerException() {
        try {
            new X509Bundle(TrustDomain.parse("example.org"), null);
            fail("should have thrown exception");
        } catch (NullPointerException e) {
            assertEquals("x509Authorities is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void TestFromAuthorities() {
        X509Certificate x509Cert1 = new DummyX509Certificate();
        X509Certificate x509Cert2 = new DummyX509Certificate();

        HashSet<X509Certificate> authorities = new HashSet<>();
        authorities.add(x509Cert1);
        authorities.add(x509Cert2);

        X509Bundle x509Bundle = new X509Bundle(TrustDomain.parse("example.org"), authorities);

        assertEquals(authorities, x509Bundle.getX509Authorities());
    }

    @Test
    void testGetBundleForTrustDomain() throws BundleNotFoundException {
        X509Bundle x509Bundle = new X509Bundle(TrustDomain.parse("example.org"));
        assertEquals(x509Bundle, x509Bundle.getBundleForTrustDomain(TrustDomain.parse("example.org")));
    }

    @Test
    void testGetBundleForTrustDomain_notBundleFound_throwsBundleNotFoundException() {
        X509Bundle x509Bundle = new X509Bundle(TrustDomain.parse("example.org"));
        try {
            x509Bundle.getBundleForTrustDomain(TrustDomain.parse("other.org"));
        } catch (BundleNotFoundException e) {
            assertEquals("No X.509 bundle found for trust domain other.org", e.getMessage());
        }
    }

    @Test
    void testGetBundleForTrustDomain_nullArgument_throwsNullPointerException() {
        X509Bundle x509Bundle = new X509Bundle(TrustDomain.parse("example.org"));
        try {
            x509Bundle.getBundleForTrustDomain(null);
            fail();
        } catch (BundleNotFoundException e) {
            fail();
        } catch (NullPointerException e) {
            assertEquals("trustDomain is marked non-null but is null", e.getMessage());
        }
    }


    @Test
    void TestLoad_Succeeds() {
        try {
            X509Bundle x509Bundle = X509Bundle.load(TrustDomain.parse("example.org"), Paths.get(toUri("testdata/x509bundle/certs.pem")));
            assertEquals(2, x509Bundle.getX509Authorities().size());
        } catch (URISyntaxException | X509BundleException e) {
            fail(e);
        }
    }

    @Test
    void TestLoad_Fails() {
        try {
            X509Bundle.load(TrustDomain.parse("example.org"), Paths.get("testdata/x509bundle/non-existent.pem"));
            fail("should have thrown exception");
        } catch (X509BundleException e) {
            assertEquals("Unable to load X.509 bundle file", e.getMessage());
        }
    }

    @Test
    void testLoad_nullTrustDomain_throwsNullPointerException() throws X509BundleException {
        try {
            X509Bundle.load(null,Paths.get("testdata/x509bundle/non-existent.pem"));
            fail("should have thrown exception");
        } catch (NullPointerException e) {
            assertEquals("trustDomain is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testLoad_nullBundlePath_throwsNullPointerException() throws X509BundleException {
        try {
            X509Bundle.load(TrustDomain.parse("example.org"), null);
            fail("should have thrown exception");
        } catch (NullPointerException e) {
            assertEquals("bundlePath is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testParse_nullTrustDomain_throwsNullPointerException() throws X509BundleException {
        try {
            X509Bundle.parse(null, "bytes".getBytes());
            fail("should have thrown exception");
        } catch (NullPointerException e) {
            assertEquals("trustDomain is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testParse_nullBundlePath_throwsNullPointerException() throws X509BundleException {
        try {
            X509Bundle.parse(TrustDomain.parse("example.org"), null);
            fail("should have thrown exception");
        } catch (NullPointerException e) {
            assertEquals("bundleBytes is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testHasAuthority_nullArgument_throwsNullPointerException() {
        X509Bundle x509Bundle = new X509Bundle(TrustDomain.parse("example.org"));
        try {
            x509Bundle.hasX509Authority(null);
            fail();
        } catch (NullPointerException e) {
            assertEquals("x509Authority is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testAddAuthority_nullArgument_throwsNullPointerException() {
        X509Bundle x509Bundle = new X509Bundle(TrustDomain.parse("example.org"));
        try {
            x509Bundle.addX509Authority(null);
            fail();
        } catch (NullPointerException e) {
            assertEquals("x509Authority is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testRemoveAuthority_nullArgument_throwsNullPointerException() {
        X509Bundle x509Bundle = new X509Bundle(TrustDomain.parse("example.org"));
        try {
            x509Bundle.removeX509Authority(null);
            fail();
        } catch (NullPointerException e) {
            assertEquals("x509Authority is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void TestX509AuthoritiesCRUD() {
        X509Bundle bundle1 = null;
        X509Bundle bundle2 = null;
        try {
            // Load bundle1, which contains a single certificate
            bundle1 = X509Bundle.load(TrustDomain.parse("example.org"), Paths.get(toUri("testdata/x509bundle/cert.pem")));

            // Load bundle2, which contains 2 certificates
            // The first certificate is the same than the one used in bundle1
            bundle2 = X509Bundle.load(TrustDomain.parse("example.org"), Paths.get(toUri("testdata/x509bundle/certs.pem")));
        } catch (URISyntaxException | X509BundleException e) {
            fail(e);
        }

        assertEquals(1, bundle1.getX509Authorities().size());
        assertEquals(2, bundle2.getX509Authorities().size());

        assertTrue(bundle2.hasX509Authority((X509Certificate) bundle1.getX509Authorities().toArray()[0]));

        // Adding a new authority increases the x509Authorities slice length
        bundle1.addX509Authority((X509Certificate) bundle2.getX509Authorities().toArray()[1]);
        assertEquals(2, bundle1.getX509Authorities().size());
        assertTrue(bundle1.hasX509Authority((X509Certificate) bundle2.getX509Authorities().toArray()[0]));
        assertTrue(bundle1.hasX509Authority((X509Certificate) bundle2.getX509Authorities().toArray()[1]));

        // If the authority already exist, it should not be added again
        bundle1.addX509Authority((X509Certificate) bundle2.getX509Authorities().toArray()[0]);
        bundle1.addX509Authority((X509Certificate) bundle2.getX509Authorities().toArray()[1]);
        assertEquals(2, bundle1.getX509Authorities().size());
        assertTrue(bundle1.hasX509Authority((X509Certificate) bundle2.getX509Authorities().toArray()[0]));
        assertTrue(bundle1.hasX509Authority((X509Certificate) bundle2.getX509Authorities().toArray()[1]));

        // Removing an authority, decreases the authority slice length
        X509Certificate cert = (X509Certificate) bundle1.getX509Authorities().toArray()[0];
        bundle1.removeX509Authority(cert);
        assertEquals(1, bundle1.getX509Authorities().size());
        assertFalse(bundle1.hasX509Authority(cert));

        // If the authority does not exist, it should keep its size
        bundle1.removeX509Authority(cert);
        assertEquals(1, bundle1.getX509Authorities().size());
        assertFalse(bundle1.hasX509Authority(cert));
    }

    @ParameterizedTest
    @MethodSource("provideX509BundleScenarios")
    void parseX509Bundle(TestCase testCase) {
        try {
            Path path = Paths.get(toUri(testCase.path));
            byte[] bytes = Files.readAllBytes(path);
            X509Bundle x509Bundle = X509Bundle.parse(testCase.trustDomain, bytes);

            if (StringUtils.isNotBlank(testCase.expectedError)) {
                fail(String.format("Error was expected: %s", testCase.expectedError));
            }

            assertNotNull(x509Bundle);
            assertEquals(testCase.trustDomain, x509Bundle.getTrustDomain());
            assertEquals(testCase.expectedNumberOfAuthorities, x509Bundle.getX509Authorities().size());
        } catch (Exception e) {
            if (StringUtils.isBlank(testCase.expectedError)) {
                fail(e);
            }
            assertEquals(testCase.expectedError, e.getMessage());
        }
    }

    static Stream<Arguments> provideX509BundleScenarios() {
        return Stream.of(
                Arguments.of(TestCase
                        .builder()
                        .name("Parse multiple certificates should succeed")
                        .path("testdata/x509bundle/certs.pem")
                        .trustDomain(TrustDomain.parse("example.org"))
                        .expectedNumberOfAuthorities(2)
                        .build()
                ),
                Arguments.of(TestCase
                        .builder()
                        .name("Parse single certificate should succeed")
                        .path("testdata/x509bundle/cert.pem")
                        .trustDomain(TrustDomain.parse("example.org"))
                        .expectedNumberOfAuthorities(1)
                        .build()
                ),
                Arguments.of(TestCase
                        .builder()
                        .name("Parse empty bytes should fail")
                        .path("testdata/x509bundle/empty.pem")
                        .trustDomain(TrustDomain.parse("example.org"))
                        .expectedError("Bundle certificates could not be parsed from bundle path")
                        .build()
                ),
                Arguments.of(TestCase
                        .builder()
                        .name("Parse non-PEM bytes should fail")
                        .path("testdata/x509bundle/not-pem.pem")
                        .trustDomain(TrustDomain.parse("example.org"))
                        .expectedError("Bundle certificates could not be parsed from bundle path")
                        .build()
                ),
                Arguments.of(TestCase
                        .builder()
                        .name("Parse should fail if no certificate block is is found")
                        .path("testdata/x509bundle/key.pem")
                        .trustDomain(TrustDomain.parse("example.org"))
                        .expectedError("Bundle certificates could not be parsed from bundle path")
                        .build()
                ),
                Arguments.of(TestCase
                        .builder()
                        .name("Parse a corrupted certificate should fail")
                        .path("testdata/x509bundle/corrupted.pem")
                        .trustDomain(TrustDomain.parse("example.org"))
                        .expectedError("Bundle certificates could not be parsed from bundle path")
                        .build()
                )
        );
    }

    @Value
    static class TestCase {
        String name;
        TrustDomain trustDomain;
        String path;
        int expectedNumberOfAuthorities;
        String expectedError;

        @Builder
        public TestCase(String name, TrustDomain trustDomain, String path, int expectedNumberOfAuthorities, String expectedError) {
            this.name = name;
            this.trustDomain = trustDomain;
            this.path = path;
            this.expectedNumberOfAuthorities = expectedNumberOfAuthorities;
            this.expectedError = expectedError;
        }
    }
}
