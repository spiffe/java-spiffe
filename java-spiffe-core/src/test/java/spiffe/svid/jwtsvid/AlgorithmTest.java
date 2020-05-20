package spiffe.svid.jwtsvid;

import lombok.Builder;
import lombok.Value;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import spiffe.Algorithm;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
                Arguments.of(TestCase.builder().name("OTHER").expectedAlgorithm(new Algorithm("OTHER")).build())
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
}