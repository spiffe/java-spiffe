package io.spiffe.svid.x509svid;

import io.spiffe.exception.InvalidSpiffeIdException;
import io.spiffe.exception.X509SvidException;
import io.spiffe.internal.DummyX509Certificate;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.utils.CertAndKeyPair;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.platform.commons.util.StringUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.stream.Stream;

import static io.spiffe.utils.TestUtils.toUri;
import static io.spiffe.utils.X509CertificateTestUtils.createCertificate;
import static io.spiffe.utils.X509CertificateTestUtils.createCertificateWithUriSans;
import static io.spiffe.utils.X509CertificateTestUtils.createRootCA;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class X509SvidTest {

    static String keyRSA = "testdata/x509svid/key-pkcs8-rsa.pem";
    static String certSingle = "testdata/x509svid/good-leaf-only.pem";
    static String leafNoDigitalSignature = "testdata/x509svid/wrong-leaf-no-digital-signature.pem";
    static String leafCRLSign = "testdata/x509svid/wrong-leaf-crl-sign.pem";
    static String leafCertSign = "testdata/x509svid/wrong-leaf-cert-sign.pem";
    static String leafCAtrue = "testdata/x509svid/wrong-leaf-ca-true.pem";
    static String leafEmptyID = "testdata/x509svid/wrong-leaf-empty-id.pem";
    static String signNoCA = "testdata/x509svid/wrong-intermediate-no-ca.pem";
    static String signNoKeyCertSign = "testdata/x509svid/wrong-intermediate-no-key-cert-sign.pem";
    static String keyECDSA = "testdata/x509svid/key-pkcs8-ecdsa.pem";
    static String certMultiple = "testdata/x509svid/good-leaf-and-intermediate.pem";
    static String corrupted = "testdata/x509svid/corrupted";
    static String keyDER = "testdata/x509svid/keyEC.der";
    static String certDER = "testdata/x509svid/cert.der";

    static Stream<Arguments> provideX509SvidScenarios() {
        return Stream.of(
                Arguments.of(TestCase
                        .builder()
                        .name("1. Single certificate and key")
                        .certsPath(certSingle)
                        .keyPath(keyRSA)
                        .hint("")
                        .expectedSpiffeId(SpiffeId.fromSegments(TrustDomain.parse("example.org"), "workload-1"))
                        .expectedNumberOfCerts(1)
                        .expectedPrivateKeyAlgorithm("RSA")
                        .expectedHint("")
                        .build()
                ),
                Arguments.of(TestCase
                        .builder()
                        .name("2. Certificate with intermediate and key")
                        .certsPath(certMultiple)
                        .keyPath(keyECDSA)
                        .hint("")
                        .expectedSpiffeId(SpiffeId.fromSegments(TrustDomain.parse("example.org"), "workload-1"))
                        .expectedNumberOfCerts(2)
                        .expectedPrivateKeyAlgorithm("EC")
                        .expectedHint("")
                        .build()
                ),
                Arguments.of(TestCase
                        .builder()
                        .name("3. Missing certificate")
                        .certsPath(keyRSA)
                        .keyPath(keyRSA)
                        .hint("")
                        .expectedError("Certificate could not be parsed from cert bytes")
                        .expectedHint("")
                        .build()
                ),
                Arguments.of(TestCase
                        .builder()
                        .name("4. Missing key")
                        .certsPath(certSingle)
                        .keyPath(certSingle)
                        .hint("")
                        .expectedError("Private Key could not be parsed from key bytes")
                        .build()
                ),
                Arguments.of(TestCase
                        .builder()
                        .name("5. Corrupted private key")
                        .certsPath(certSingle)
                        .keyPath(corrupted)
                        .hint("")
                        .expectedError("Private Key could not be parsed from key bytes")
                        .build()
                ),
                Arguments.of(TestCase
                        .builder()
                        .name("6. Corrupted certificate")
                        .certsPath(corrupted)
                        .keyPath(keyRSA)
                        .hint("")
                        .expectedError("Certificate could not be parsed from cert bytes")
                        .build()
                ),
                Arguments.of(TestCase
                        .builder()
                        .name("7. Certificate without SPIFFE ID")
                        .certsPath(leafEmptyID)
                        .keyPath(keyRSA)
                        .hint("")
                        .expectedError("Leaf certificate must contain exactly one URI SAN")
                        .build()
                ),
                Arguments.of(TestCase
                        .builder()
                        .name("8. Leaf certificate with CA flag set to true")
                        .certsPath(leafCAtrue)
                        .keyPath(keyRSA)
                        .hint("")
                        .expectedError("Leaf certificate must not have CA flag set to true")
                        .build()
                ),
                Arguments.of(TestCase
                        .builder()
                        .name("9. Leaf certificate without digitalSignature as key usage")
                        .certsPath(leafNoDigitalSignature)
                        .keyPath(keyRSA)
                        .hint("")
                        .expectedError("Leaf certificate must have 'digitalSignature' as key usage")
                        .build()
                ),
                Arguments.of(TestCase
                        .builder()
                        .name("10. Leaf certificate with certSign as key usage")
                        .certsPath(leafCertSign)
                        .keyPath(keyRSA)
                        .hint("")
                        .expectedError("Leaf certificate must not have 'keyCertSign' as key usage")
                        .build()
                ),
                Arguments.of(TestCase
                        .builder()
                        .name("11. Leaf certificate with cRLSign as key usage")
                        .certsPath(leafCRLSign)
                        .keyPath(keyRSA)
                        .hint("")
                        .expectedError("Leaf certificate must not have 'cRLSign' as key usage")
                        .build()
                ),
                Arguments.of(TestCase
                        .builder()
                        .name("12. Signing certificate without CA flag")
                        .certsPath(signNoCA)
                        .keyPath(keyRSA)
                        .hint("")
                        .expectedError("Signing certificate must have CA flag set to true")
                        .build()
                ),
                Arguments.of(TestCase
                        .builder()
                        .name("13. Signing certificate without CA flag")
                        .certsPath(signNoKeyCertSign)
                        .keyPath(keyRSA)
                        .hint("")
                        .expectedError("Signing certificate must have 'keyCertSign' as key usage")
                        .build()
                ),
                Arguments.of(TestCase
                        .builder()
                        .name("14. SVID with non-empty hint")
                        .certsPath(certSingle)
                        .keyPath(keyRSA)
                        .hint("internal")
                        .expectedSpiffeId(SpiffeId.fromSegments(TrustDomain.parse("example.org"), "workload-1"))
                        .expectedNumberOfCerts(1)
                        .expectedPrivateKeyAlgorithm("RSA")
                        .expectedHint("internal")
                        .build()
                )
        );
    }

    @Test
    void testLoad_Success() throws URISyntaxException {

        Path certPath = Paths.get(toUri(certSingle));
        Path keyPath = Paths.get(toUri(keyRSA));
        try {
            X509Svid x509Svid = X509Svid.load(certPath, keyPath);
            assertEquals("spiffe://example.org/workload-1", x509Svid.getSpiffeId().toString());
        } catch (X509SvidException e) {
            fail(e);
        }
    }

    @Test
    void testParseRaw() throws URISyntaxException, IOException {
        Path certPath = Paths.get(toUri(certDER));
        Path keyPath = Paths.get(toUri(keyDER));

        byte[] certBytes = Files.readAllBytes(certPath);
        byte[] keyBytes = Files.readAllBytes(keyPath);

        try {
            X509Svid x509Svid = X509Svid.parseRaw(certBytes, keyBytes, "external");
            assertEquals("spiffe://example.org/workload-server", x509Svid.getSpiffeId().toString());
            assertEquals("external", x509Svid.getHint());

        } catch (X509SvidException e) {
            fail(e);
        }
    }

    @Test
    void testParseRawNullCertsBytesArgument() {
        try {
            X509Svid.parseRaw(null, new byte[]{});
            fail();
        } catch (NullPointerException e) {
            assertEquals("certsBytes must not be null", e.getMessage());
        } catch (X509SvidException e) {
            fail();
        }
    }

    @Test
    void testParseRawNullPrivateKeyBytesArgument() {
        try {
            X509Svid.parseRaw(new byte[]{}, null);
            fail();
        } catch (NullPointerException e) {
            assertEquals("privateKeyBytes must not be null", e.getMessage());
        } catch (X509SvidException e) {
            fail();
        }
    }

    @Test
    void testLoad_FailsCannotReadCertFile() throws URISyntaxException {
        Path keyPath = Paths.get(toUri(keyRSA));
        try {
            X509Svid.load(Paths.get("not-existent-cert"), keyPath);
            fail("should have thrown IOException");
        } catch (X509SvidException e) {
            assertEquals("Cannot read certificate file", e.getMessage());
        }
    }

    @Test
    void testLoad_FailsCannotReadKeyFile() throws URISyntaxException {
        Path certPath = Paths.get(toUri(certSingle));
        try {
            X509Svid.load(certPath, Paths.get("not-existent-key"));
            fail("should have thrown IOException");
        } catch (X509SvidException e) {
            assertEquals("Cannot read private key file", e.getMessage());
        }
    }

    @Test
    void testLoad_nullCertFilePath_throwsNullPointerException() throws URISyntaxException {
        try {
            X509Svid.load(null, Paths.get(toUri(keyRSA)));
            fail("should have thrown exception");
        } catch (NullPointerException | X509SvidException e) {
            assertEquals("certsFilePath must not be null", e.getMessage());
        }
    }

    @Test
    void testLoad_nullKeyFilePath_throwsNullPointerException() throws URISyntaxException, X509SvidException {
        try {
            X509Svid.load(Paths.get(toUri(certSingle)), null);
            fail("should have thrown exception");
        } catch (NullPointerException e) {
            assertEquals("privateKeyFilePath must not be null", e.getMessage());
        }
    }

    @Test
    void testParse_nullByteArray_throwsNullPointerException() throws X509SvidException {
        try {
            X509Svid.parse(null, "key".getBytes());
            fail("should have thrown exception");
        } catch (NullPointerException e) {
            assertEquals("certsBytes must not be null", e.getMessage());
        }
    }

    @Test
    void testParse_nullKeyByteArray_throwsNullPointerException() throws X509SvidException {
        try {
            X509Svid.parse("cert".getBytes(), null);
            fail("should have thrown exception");
        } catch (NullPointerException e) {
            assertEquals("privateKeyBytes must not be null", e.getMessage());
        }
    }

    @Test
    void testGetLeaf() throws URISyntaxException, X509SvidException {
        Path certPath = Paths.get(toUri(certSingle));
        Path keyPath = Paths.get(toUri(keyRSA));
        X509Svid x509Svid = X509Svid.load(certPath, keyPath);
        assertEquals(x509Svid.getChain().get(0), x509Svid.getLeaf());
    }

    @Test
    void testGetChainArray() throws URISyntaxException, X509SvidException {
        Path certPath = Paths.get(toUri(certMultiple));
        Path keyPath = Paths.get(toUri(keyECDSA));
        X509Svid x509Svid = X509Svid.load(certPath, keyPath);
        X509Certificate[] x509CertificatesArray = x509Svid.getChainArray();
        assertEquals(x509Svid.getChain().get(0), x509CertificatesArray[0]);
        assertEquals(x509Svid.getChain().get(1), x509CertificatesArray[1]);
    }

    @Test
    void parseRaw_leafSpiffeIdWithoutPath_isRejected() throws Exception {
        CertAndKeyPair rootCa = createRootCA("C = US, O = SPIFFE", "spiffe://example.org");
        CertAndKeyPair leaf = createCertificate("C = US, O = SPIRE", "C = US, O = SPIFFE", "spiffe://example.org", rootCa, false);

        byte[] certBytes = leaf.getCertificate().getEncoded();
        byte[] keyBytes = leaf.getKeyPair().getPrivate().getEncoded();

        X509SvidException exception = assertThrows(
                X509SvidException.class,
                () -> X509Svid.parseRaw(certBytes, keyBytes)
        );

        assertEquals("Leaf certificate SPIFFE ID must have a non-root path", exception.getMessage());
    }

    @Test
    void parseRaw_leafSpiffeIdWithRootOnlyPath_isRejected() throws Exception {
        CertAndKeyPair rootCa = createRootCA("C = US, O = SPIFFE", "spiffe://example.org");
        CertAndKeyPair leaf = createCertificate("C = US, O = SPIRE", "C = US, O = SPIFFE", "spiffe://example.org/", rootCa, false);

        byte[] certBytes = leaf.getCertificate().getEncoded();
        byte[] keyBytes = leaf.getKeyPair().getPrivate().getEncoded();

        X509SvidException exception = assertThrows(
                X509SvidException.class,
                () -> X509Svid.parseRaw(certBytes, keyBytes)
        );

        assertEquals("Certificate contains invalid SPIFFE ID in the URI SAN", exception.getMessage());
        assertInstanceOf(CertificateException.class, exception.getCause());
        assertInstanceOf(InvalidSpiffeIdException.class, exception.getCause().getCause());
        assertEquals("Path cannot have a trailing slash", exception.getCause().getCause().getMessage());
    }

   @Test
    void parseRaw_leafWithMultipleUriSans_isRejected() throws Exception {
        CertAndKeyPair rootCa = createRootCA("C = US, O = SPIFFE", "spiffe://example.org");
        CertAndKeyPair leaf = createCertificateWithUriSans(
                "C = US, O = SPIRE",
                "C = US, O = SPIFFE",
                Arrays.asList("spiffe://example.org/workload", "https://example.org/workload"),
                rootCa,
                false
        );

        byte[] certBytes = leaf.getCertificate().getEncoded();
        byte[] keyBytes = leaf.getKeyPair().getPrivate().getEncoded();

        X509SvidException exception = assertThrows(
                X509SvidException.class,
                () -> X509Svid.parseRaw(certBytes, keyBytes)
        );

        assertEquals("Leaf certificate must contain exactly one URI SAN", exception.getMessage());
    }

    static Stream<Arguments> provideMarshalScenarios() {
        return Stream.of(
                Arguments.of(certSingle, keyRSA),
                Arguments.of(certMultiple, keyECDSA)
        );
    }

    @ParameterizedTest
    @MethodSource("provideMarshalScenarios")
    void testMarshal_roundTripsThroughParse(String certsPath, String keyPath) throws Exception {
        X509Svid x509Svid = X509Svid.load(Paths.get(toUri(certsPath)), Paths.get(toUri(keyPath)));

        X509Svid parsed = X509Svid.parse(x509Svid.marshalCertificates(), x509Svid.marshalPrivateKey());

        assertSameSvid(x509Svid, parsed);
    }

    @ParameterizedTest
    @MethodSource("provideMarshalScenarios")
    void testMarshal_roundTripsThroughLoad(String certsPath, String keyPath, @TempDir Path tempDir) throws Exception {
        X509Svid x509Svid = X509Svid.load(Paths.get(toUri(certsPath)), Paths.get(toUri(keyPath)));
        Path marshaledCertsPath = Files.write(tempDir.resolve("svid.pem"), x509Svid.marshalCertificates());
        Path marshaledKeyPath = Files.write(tempDir.resolve("svid.key"), x509Svid.marshalPrivateKey());

        X509Svid loaded = X509Svid.load(marshaledCertsPath, marshaledKeyPath);

        assertSameSvid(x509Svid, loaded);
    }

    @ParameterizedTest
    @MethodSource("provideMarshalScenarios")
    void testMarshalRaw_roundTripsThroughParseRaw(String certsPath, String keyPath) throws Exception {
        X509Svid x509Svid = X509Svid.load(Paths.get(toUri(certsPath)), Paths.get(toUri(keyPath)));

        X509Svid parsed = X509Svid.parseRaw(x509Svid.marshalRawCertificates(), x509Svid.marshalRawPrivateKey());

        assertSameSvid(x509Svid, parsed);
    }

    @Test
    void testMarshalRaw_returnsDerEncoding() throws Exception {
        byte[] certBytes = Files.readAllBytes(Paths.get(toUri(certDER)));
        byte[] keyBytes = Files.readAllBytes(Paths.get(toUri(keyDER)));
        X509Svid x509Svid = X509Svid.parseRaw(certBytes, keyBytes);

        assertArrayEquals(certBytes, x509Svid.marshalRawCertificates());
        assertArrayEquals(x509Svid.getPrivateKey().getEncoded(), x509Svid.marshalRawPrivateKey());
    }

    @Test
    void testMarshalCertificates_writesOnePemBlockPerCertificateLeafFirst() throws Exception {
        X509Svid x509Svid = X509Svid.load(Paths.get(toUri(certMultiple)), Paths.get(toUri(keyECDSA)));

        String pem = new String(x509Svid.marshalCertificates(), StandardCharsets.US_ASCII);

        String[] blocks = pem.split("(?<=-----END CERTIFICATE-----\n)");
        assertEquals(2, blocks.length);
        for (int i = 0; i < blocks.length; i++) {
            assertTrue(blocks[i].startsWith("-----BEGIN CERTIFICATE-----\n"));
            assertTrue(blocks[i].endsWith("\n-----END CERTIFICATE-----\n"));
            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(blocks[i].getBytes(StandardCharsets.US_ASCII)));
            assertEquals(x509Svid.getChain().get(i), certificate);
        }
        assertPemLinesAreWrapped(pem);
    }

    @Test
    void testMarshalPrivateKey_writesPkcs8PemBlock() throws Exception {
        X509Svid x509Svid = X509Svid.load(Paths.get(toUri(certSingle)), Paths.get(toUri(keyRSA)));

        String pem = new String(x509Svid.marshalPrivateKey(), StandardCharsets.US_ASCII);

        assertTrue(pem.startsWith("-----BEGIN PRIVATE KEY-----\n"));
        assertTrue(pem.endsWith("\n-----END PRIVATE KEY-----\n"));
        String base64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("\n", "");
        assertArrayEquals(x509Svid.getPrivateKey().getEncoded(), Base64.getDecoder().decode(base64));
        assertPemLinesAreWrapped(pem);
    }

    @Test
    void testMarshal_certificateCannotBeEncoded_throwsX509SvidException() throws Exception {
        X509Svid x509Svid = X509Svid.load(Paths.get(toUri(certSingle)), Paths.get(toUri(keyRSA)));
        CertificateEncodingException encodingException = new CertificateEncodingException("encoding error");
        x509Svid.chain = Collections.singletonList(new DummyX509Certificate() {
            @Override
            public byte[] getEncoded() throws CertificateEncodingException {
                throw encodingException;
            }
        });

        X509SvidException pemException = assertThrows(X509SvidException.class, x509Svid::marshalCertificates);
        assertEquals("Certificate could not be encoded", pemException.getMessage());
        assertSame(encodingException, pemException.getCause());

        X509SvidException derException = assertThrows(X509SvidException.class, x509Svid::marshalRawCertificates);
        assertEquals("Certificate could not be encoded", derException.getMessage());
        assertSame(encodingException, derException.getCause());
    }

    static Stream<Arguments> provideNonPkcs8PrivateKeys() {
        return Stream.of(
                Arguments.of("RAW", new byte[]{1, 2, 3}),
                Arguments.of(null, null),
                Arguments.of("PKCS#8", null)
        );
    }

    @ParameterizedTest
    @MethodSource("provideNonPkcs8PrivateKeys")
    void testMarshal_privateKeyCannotBeEncodedAsPkcs8_throwsX509SvidException(String format, byte[] encoded)
            throws Exception {
        X509Svid x509Svid = X509Svid.load(Paths.get(toUri(certSingle)), Paths.get(toUri(keyRSA)));
        x509Svid.privateKey = new PrivateKey() {
            @Override
            public String getAlgorithm() {
                return "RSA";
            }

            @Override
            public String getFormat() {
                return format;
            }

            @Override
            public byte[] getEncoded() {
                return encoded;
            }
        };

        X509SvidException pemException = assertThrows(X509SvidException.class, x509Svid::marshalPrivateKey);
        assertEquals("Private key could not be encoded as PKCS#8", pemException.getMessage());

        X509SvidException derException = assertThrows(X509SvidException.class, x509Svid::marshalRawPrivateKey);
        assertEquals("Private key could not be encoded as PKCS#8", derException.getMessage());
    }

    private static void assertSameSvid(X509Svid expected, X509Svid actual) {
        assertEquals(expected.getSpiffeId(), actual.getSpiffeId());
        assertEquals(expected.getChain(), actual.getChain());
        assertEquals(expected.getPrivateKey().getAlgorithm(), actual.getPrivateKey().getAlgorithm());
        assertArrayEquals(expected.getPrivateKey().getEncoded(), actual.getPrivateKey().getEncoded());
    }

    private static void assertPemLinesAreWrapped(String pem) {
        for (String line : pem.split("\n")) {
            assertTrue(line.length() <= 64, "PEM line longer than 64 characters: " + line);
        }
    }

    @ParameterizedTest
    @MethodSource("provideX509SvidScenarios")
    void parseX509Svid(TestCase testCase) {
        try {
            Path certPath = Paths.get(toUri(testCase.certsPath));
            Path keyPath = Paths.get(toUri(testCase.keyPath));
            byte[] certBytes = Files.readAllBytes(certPath);
            byte[] keyBytes = Files.readAllBytes(keyPath);

            X509Svid x509Svid = X509Svid.parse(certBytes, keyBytes, testCase.hint);

            if (StringUtils.isNotBlank(testCase.expectedError)) {
                fail(String.format("Error was expected: %s", testCase.expectedError));
            }

            assertNotNull(x509Svid);
            assertNotNull(x509Svid.getSpiffeId());
            assertNotNull(x509Svid.getChain());
            assertNotNull(x509Svid.getPrivateKey());
            assertEquals(testCase.expectedNumberOfCerts, x509Svid.getChain().size());
            assertEquals(testCase.expectedSpiffeId, x509Svid.getSpiffeId());
            assertEquals(testCase.expectedPrivateKeyAlgorithm, x509Svid.getPrivateKey().getAlgorithm());
            assertEquals(testCase.expectedHint, x509Svid.getHint());

        } catch (Exception e) {
            if (StringUtils.isBlank(testCase.expectedError)) {
                fail(e);
            }
            assertEquals(testCase.expectedError, e.getMessage());
        }
    }

    static class TestCase {
        String name;
        String certsPath;
        String hint;
        String keyPath;
        SpiffeId expectedSpiffeId;
        int expectedNumberOfCerts;
        String expectedPrivateKeyAlgorithm;
        String expectedHint;
        String expectedError;

        public TestCase(String name,
                        String certsPath,
                        String keyPath,
                        String hint,
                        SpiffeId expectedSpiffeId,
                        int expectedNumberOfCerts,
                        String expectedPrivateKeyAlgorithm,
                        String expectedHint,
                        String expectedError) {

            this.name = name;
            this.certsPath = certsPath;
            this.keyPath = keyPath;
            this.hint = hint;
            this.expectedSpiffeId = expectedSpiffeId;
            this.expectedNumberOfCerts = expectedNumberOfCerts;
            this.expectedPrivateKeyAlgorithm = expectedPrivateKeyAlgorithm;
            this.expectedHint = expectedHint;
            this.expectedError = expectedError;
        }

        // ----- Builder -----

        public static Builder builder() {
            return new Builder();
        }

        public static final class Builder {
            private String name;
            private String certsPath;
            private String keyPath;
            private String hint;
            private SpiffeId expectedSpiffeId;
            private int expectedNumberOfCerts;
            private String expectedPrivateKeyAlgorithm;
            private String expectedHint;
            private String expectedError;

            public Builder name(String name) {
                this.name = name;
                return this;
            }

            public Builder certsPath(String certsPath) {
                this.certsPath = certsPath;
                return this;
            }

            public Builder keyPath(String keyPath) {
                this.keyPath = keyPath;
                return this;
            }

            public Builder hint(String hint) {
                this.hint = hint;
                return this;
            }

            public Builder expectedSpiffeId(SpiffeId expectedSpiffeId) {
                this.expectedSpiffeId = expectedSpiffeId;
                return this;
            }

            public Builder expectedNumberOfCerts(int expectedNumberOfCerts) {
                this.expectedNumberOfCerts = expectedNumberOfCerts;
                return this;
            }

            public Builder expectedPrivateKeyAlgorithm(String expectedPrivateKeyAlgorithm) {
                this.expectedPrivateKeyAlgorithm = expectedPrivateKeyAlgorithm;
                return this;
            }

            public Builder expectedHint(String expectedHint) {
                this.expectedHint = expectedHint;
                return this;
            }

            public Builder expectedError(String expectedError) {
                this.expectedError = expectedError;
                return this;
            }

            public TestCase build() {
                return new TestCase(
                        name,
                        certsPath,
                        keyPath,
                        hint,
                        expectedSpiffeId,
                        expectedNumberOfCerts,
                        expectedPrivateKeyAlgorithm,
                        expectedHint,
                        expectedError
                );
            }
        }
    }
}
