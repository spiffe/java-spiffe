package spiffe.svid.jwtsvid;

import lombok.Builder;
import lombok.Value;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import spiffe.Algorithm;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AlgorithmTest {

    @ParameterizedTest
    @MethodSource("provideTestCases")
    void parse(TestCase testCase) {
        Algorithm signatureAlgorithm = Algorithm.parse(testCase.name);
        assertEquals(testCase.expectedAlgorithm, signatureAlgorithm);
        assertEquals(testCase.name, signatureAlgorithm.getName());
    }

    static Stream<Arguments> provideTestCases() {
        return Stream.of(
                Arguments.of(TestCase.builder().name("RS256").expectedAlgorithm(Algorithm.RS256).build()),
                Arguments.of(TestCase.builder().name("RS384").expectedAlgorithm(Algorithm.RS384).build()),
                Arguments.of(TestCase.builder().name("RS512").expectedAlgorithm(Algorithm.RS512).build()),
                Arguments.of(TestCase.builder().name("ES256").expectedAlgorithm(Algorithm.ES256).build()),
                Arguments.of(TestCase.builder().name("ES384").expectedAlgorithm(Algorithm.ES384).build()),
                Arguments.of(TestCase.builder().name("ES512").expectedAlgorithm(Algorithm.ES512).build()),
                Arguments.of(TestCase.builder().name("PS256").expectedAlgorithm(Algorithm.PS256).build()),
                Arguments.of(TestCase.builder().name("PS384").expectedAlgorithm(Algorithm.PS384).build()),
                Arguments.of(TestCase.builder().name("PS512").expectedAlgorithm(Algorithm.PS512).build()),
                Arguments.of(TestCase.builder().name("OTHER").expectedAlgorithm(Algorithm.OTHER).build())
        );
    }

    @Value
    static class TestCase {
        String name;
        Algorithm expectedAlgorithm;

        @Builder
        public TestCase(String name, Algorithm expectedAlgorithm) {
            this.name = name;
            this.expectedAlgorithm = expectedAlgorithm;
        }
    }

    @Test
    void testParseFamilyRSA() {
        Algorithm.Family rsa = Algorithm.Family.parse("RSA");
        assertEquals(Algorithm.Family.RSA, rsa);
        assertTrue(rsa.contains(Algorithm.RS256));
        assertTrue(rsa.contains(Algorithm.RS384));
        assertTrue(rsa.contains(Algorithm.RS512));
        assertTrue(rsa.contains(Algorithm.PS256));
        assertTrue(rsa.contains(Algorithm.PS384));
        assertTrue(rsa.contains(Algorithm.PS512));
    }

    @Test
    void testParseFamilyEC() {
        Algorithm.Family ec = Algorithm.Family.parse("EC");
        assertEquals(Algorithm.Family.EC, ec);
        assertTrue(ec.contains(Algorithm.ES256));
        assertTrue(ec.contains(Algorithm.ES384));
        assertTrue(ec.contains(Algorithm.ES512));
    }

    @Test
    void testParseFamilyOTHER() {
        Algorithm.Family other = Algorithm.Family.parse("unknown family");
        assertEquals(Algorithm.Family.OTHER, other);
    }
}