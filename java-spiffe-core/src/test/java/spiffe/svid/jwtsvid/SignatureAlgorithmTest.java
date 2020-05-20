package spiffe.svid.jwtsvid;

import lombok.Builder;
import lombok.Value;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import spiffe.SignatureAlgorithm;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SignatureAlgorithmTest {

    @ParameterizedTest
    @MethodSource("provideTestCases")
    void parse(TestCase testCase) {
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.parse(testCase.name);
        assertEquals(testCase.expectedAlgorithm, signatureAlgorithm);
        assertEquals(testCase.name, signatureAlgorithm.getName());
    }

    static Stream<Arguments> provideTestCases() {
        return Stream.of(
                Arguments.of(TestCase.builder().name("RS256").expectedAlgorithm(SignatureAlgorithm.RS256).build()),
                Arguments.of(TestCase.builder().name("RS384").expectedAlgorithm(SignatureAlgorithm.RS384).build()),
                Arguments.of(TestCase.builder().name("RS512").expectedAlgorithm(SignatureAlgorithm.RS512).build()),
                Arguments.of(TestCase.builder().name("ES256").expectedAlgorithm(SignatureAlgorithm.ES256).build()),
                Arguments.of(TestCase.builder().name("ES384").expectedAlgorithm(SignatureAlgorithm.ES384).build()),
                Arguments.of(TestCase.builder().name("ES512").expectedAlgorithm(SignatureAlgorithm.ES512).build()),
                Arguments.of(TestCase.builder().name("PS256").expectedAlgorithm(SignatureAlgorithm.PS256).build()),
                Arguments.of(TestCase.builder().name("PS384").expectedAlgorithm(SignatureAlgorithm.PS384).build()),
                Arguments.of(TestCase.builder().name("PS512").expectedAlgorithm(SignatureAlgorithm.PS512).build()),
                Arguments.of(TestCase.builder().name("OTHER").expectedAlgorithm(new SignatureAlgorithm("OTHER")).build())
        );
    }

    @Value
    static class TestCase {
        String name;
        SignatureAlgorithm expectedAlgorithm;

        @Builder
        public TestCase(String name, SignatureAlgorithm expectedAlgorithm) {
            this.name = name;
            this.expectedAlgorithm = expectedAlgorithm;
        }
    }
}