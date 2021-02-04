package io.spiffe.svid.jwtsvid;

import io.spiffe.internal.JwtSignatureAlgorithm;
import lombok.Builder;
import lombok.Value;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class JwtSignatureAlgorithmTest {

    @ParameterizedTest
    @MethodSource("provideTestCases")
    void parse(TestCase testCase) {
        JwtSignatureAlgorithm signatureAlgorithm = JwtSignatureAlgorithm.parse(testCase.name);
        assertEquals(testCase.expectedAlgorithm, signatureAlgorithm);
        assertEquals(testCase.name, signatureAlgorithm.getName());
    }

    static Stream<Arguments> provideTestCases() {
        return Stream.of(
                Arguments.of(TestCase.builder().name("RS256").expectedAlgorithm(JwtSignatureAlgorithm.RS256).build()),
                Arguments.of(TestCase.builder().name("RS384").expectedAlgorithm(JwtSignatureAlgorithm.RS384).build()),
                Arguments.of(TestCase.builder().name("RS512").expectedAlgorithm(JwtSignatureAlgorithm.RS512).build()),
                Arguments.of(TestCase.builder().name("ES256").expectedAlgorithm(JwtSignatureAlgorithm.ES256).build()),
                Arguments.of(TestCase.builder().name("ES384").expectedAlgorithm(JwtSignatureAlgorithm.ES384).build()),
                Arguments.of(TestCase.builder().name("ES512").expectedAlgorithm(JwtSignatureAlgorithm.ES512).build()),
                Arguments.of(TestCase.builder().name("PS256").expectedAlgorithm(JwtSignatureAlgorithm.PS256).build()),
                Arguments.of(TestCase.builder().name("PS384").expectedAlgorithm(JwtSignatureAlgorithm.PS384).build()),
                Arguments.of(TestCase.builder().name("PS512").expectedAlgorithm(JwtSignatureAlgorithm.PS512).build())
        );
    }

    @Value
    static class TestCase {
        String name;
        JwtSignatureAlgorithm expectedAlgorithm;

        @Builder
        public TestCase(String name, JwtSignatureAlgorithm expectedAlgorithm) {
            this.name = name;
            this.expectedAlgorithm = expectedAlgorithm;
        }
    }

    @Test
    void testParseFamilyRSA() {
        JwtSignatureAlgorithm.Family rsa = JwtSignatureAlgorithm.Family.parse("RSA");
        assertEquals(JwtSignatureAlgorithm.Family.RSA, rsa);
        assertTrue(rsa.contains(JwtSignatureAlgorithm.RS256));
        assertTrue(rsa.contains(JwtSignatureAlgorithm.RS384));
        assertTrue(rsa.contains(JwtSignatureAlgorithm.RS512));
        assertTrue(rsa.contains(JwtSignatureAlgorithm.PS256));
        assertTrue(rsa.contains(JwtSignatureAlgorithm.PS384));
        assertTrue(rsa.contains(JwtSignatureAlgorithm.PS512));
    }

    @Test
    void testParseFamilyEC() {
        JwtSignatureAlgorithm.Family ec = JwtSignatureAlgorithm.Family.parse("EC");
        assertEquals(JwtSignatureAlgorithm.Family.EC, ec);
        assertTrue(ec.contains(JwtSignatureAlgorithm.ES256));
        assertTrue(ec.contains(JwtSignatureAlgorithm.ES384));
        assertTrue(ec.contains(JwtSignatureAlgorithm.ES512));
    }

    @Test
    void testParseUnknownFamily() {
        try {
            JwtSignatureAlgorithm.Family.parse("unknown family");
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("Unsupported JWT token family algorithm: unknown family", e.getMessage());
        }
    }

    @Test
    void testParseUnsupportedAlgorithm() {
        try {
            JwtSignatureAlgorithm.parse("HS256");
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("Unsupported JWT token algorithm: HS256", e.getMessage());
        }
    }
}