package io.spiffe.spiffeid;

import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class SpiffeIdTest {

    @Test
    void toString_SpiffeId_ReturnsTheSpiffeIdInAStringFormatIncludingTheSchema() {
        val trustDomain = TrustDomain.of("trust-domain.org");
        val spiffeId = SpiffeId.of(trustDomain, "path1", "path2", "path3");

        val spiffeIdToString = spiffeId.toString();

        assertEquals("spiffe://trust-domain.org/path1/path2/path3", spiffeIdToString);
    }

    @ParameterizedTest
    @MethodSource("provideTestValidSpiffeIds")
    void testParseValidSpiffeId(String input, TrustDomain expectedTrustDomain, String expectedPath) {
        SpiffeId result;
        try {
            result = SpiffeId.parse(input);
            assertEquals(expectedTrustDomain, result.getTrustDomain());
            assertEquals(expectedPath, result.getPath());
        } catch (Exception e) {
            fail("Unexpected error", e);
        }
    }

    static Stream<Arguments> provideTestValidSpiffeIds() {
        return Stream.of(
                Arguments.of("spiffe://example.org", TrustDomain.of("example.org"), ""),
                Arguments.of("spiffe://example.org/path", TrustDomain.of("example.org"), "/path"),
                Arguments.of("spiffe://example.org/path1/path2", TrustDomain.of("example.org"), "/path1/path2"),
                Arguments.of("spiffe://example.org/PATH1/PATH2", TrustDomain.of("example.org"), "/PATH1/PATH2"),
                Arguments.of("SPIFFE://EXAMPLE.ORG/path1/path2", TrustDomain.of("example.org"), "/path1/path2"),
                Arguments.of("spiffe://example.org/p!a$t&h'/(e)l*e+m,e;n=t", TrustDomain.of("example.org"), "/p!a$t&h'/(e)l*e+m,e;n=t"),
                Arguments.of("spiffe://example.org/p@th", TrustDomain.of("example.org"), "/p@th"),
                Arguments.of("spiffe://example.org/pa:th/element:", TrustDomain.of("example.org"), "/pa:th/element:"),
                Arguments.of("  spiffe://domain.test/path1/path2  ", TrustDomain.of("domain.test"), "/path1/path2"),
                Arguments.of("spiffe://example.org/9eebccd2-12bf-40a6-b262-65fe0487d453", TrustDomain.of("example.org"), "/9eebccd2-12bf-40a6-b262-65fe0487d453")
        );
    }

    @ParameterizedTest
    @MethodSource("provideInvalidSpiffeIds")
    void testParseInvalidSpiffeId(String input, String expected) {
        SpiffeId result;
        try {
            result = SpiffeId.parse(input);
            assertEquals(expected, result.toString());
        } catch (Exception e) {
            assertEquals(expected, e.getMessage());
        }
    }

    static Stream<Arguments> provideInvalidSpiffeIds() {
        return Stream.of(
                Arguments.of("", "SPIFFE ID cannot be empty"),
                Arguments.of(null, "SPIFFE ID cannot be empty"),
                Arguments.of("192.168.2.2:6688", "SPIFFE ID: malformed URI: 192.168.2.2:6688"),
                Arguments.of("http://domain.test/path/element", "SPIFFE ID: invalid scheme"),
                Arguments.of("spiffe:///path/element", "SPIFFE ID: trust domain is empty"),
                Arguments.of("spiffe://domain.test/path/element?query=1", "SPIFFE ID: query is not allowed"),
                Arguments.of("spiffe://domain.test/path/element?#fragment-1", "SPIFFE ID: fragment is not allowed"),
                Arguments.of("spiffe://domain.test:8080/path/element", "SPIFFE ID: port is not allowed"),
                Arguments.of("spiffe://user:password@test.org/path/element", "SPIFFE ID: user info is not allowed"),
                Arguments.of("spiffe:path/element", "SPIFFE ID: trust domain is empty"),
                Arguments.of("spiffe:/path/element", "SPIFFE ID: trust domain is empty"),
                Arguments.of("spiffe://domain.test/path/elem%5uent", "SPIFFE ID: malformed URI: spiffe://domain.test/path/elem%5uent")
        );
    }

    @ParameterizedTest
    @MethodSource("provideValidTrustDomainAndPaths")
    void testOf(TrustDomain inputTrustDomain, String[] inputPath, SpiffeId expectedSpiffeId) {
        SpiffeId result;
        try {
            result = SpiffeId.of(inputTrustDomain, inputPath);
            assertEquals(result, expectedSpiffeId);
        } catch (Exception e) {
            fail("Unexpected error", e);
        }
    }

    static Stream<Arguments> provideValidTrustDomainAndPaths() {
        return Stream.of(
                Arguments.of(TrustDomain.of("example.org"), new String[]{""}, SpiffeId.parse("spiffe://example.org")),
                Arguments.of(TrustDomain.of("example.org"), new String[]{"path"}, SpiffeId.parse("spiffe://example.org/path")),
                Arguments.of(TrustDomain.of("example.org"), new String[]{"path1", "path2"}, SpiffeId.parse("spiffe://example.org/path1/path2")),
                Arguments.of(TrustDomain.of("example.org"), new String[]{"PATH1", "PATH2"}, SpiffeId.parse("spiffe://example.org/PATH1/PATH2")),
                Arguments.of(TrustDomain.of("EXAMPLE.ORG"), new String[]{"path1", "path2"}, SpiffeId.parse("spiffe://example.org/path1/path2")),
                Arguments.of(TrustDomain.of("example.org"), new String[]{"p!a$t&h'", "(e)l*e+m,e;n=t"}, SpiffeId.parse("spiffe://example.org/p!a$t&h'/(e)l*e+m,e;n=t")),
                Arguments.of(TrustDomain.of("example.org"), new String[]{"p@th"}, SpiffeId.parse("spiffe://example.org/p@th")),
                Arguments.of(TrustDomain.of("example.org"), new String[]{"p:ath", "element:"}, SpiffeId.parse("spiffe://example.org/p:ath/element:")),
                Arguments.of(TrustDomain.of("  example.org  "), new String[]{"  path1  ", "  path2  "}, SpiffeId.parse("spiffe://example.org/path1/path2")),
                Arguments.of(TrustDomain.of("example.org"), new String[]{"9eebccd2-12bf-40a6-b262-65fe0487d453"}, SpiffeId.parse("spiffe://example.org/9eebccd2-12bf-40a6-b262-65fe0487d453"))
        );
    }

    @ParameterizedTest
    @MethodSource("provideInvalidArguments")
    void testOfInvalid(TrustDomain trustDomain, String[] inputPath, String expectedError) {
        SpiffeId result;
        try {
            SpiffeId.of(trustDomain, inputPath);
            fail(String.format("Expected error %s", expectedError));
        } catch (Exception e) {
            assertEquals(expectedError, e.getMessage());
        }
    }

    static Stream<Arguments> provideInvalidArguments() {
        return Stream.of(
                Arguments.of(null, new String[]{""}, "trustDomain is marked non-null but is null"),
                Arguments.of(TrustDomain.of("domain.test"), new String[]{"elem%5uent"}, "SPIFFE ID: malformed URI: spiffe://domain.test/elem%5uent")
        );
    }

    @Test
    void memberOf_aTrustDomainAndASpiffeIdWithSameTrustDomain_ReturnsTrue() {
        val trustDomain = TrustDomain.of("trust-domain.org");
        val spiffeId = SpiffeId.of(trustDomain, "path1", "path2");

        val isMemberOf = spiffeId.memberOf(TrustDomain.of("trust-domain.org"));

        assertTrue(isMemberOf);
    }

    @Test
    void memberOf_aTrustDomainAndASpiffeIdWithDifferentTrustDomain_ReturnsFalse() {
        val trustDomain = TrustDomain.of("trust-domain.org");
        val spiffeId = SpiffeId.of(trustDomain, "path1", "path2");

        val isMemberOf = spiffeId.memberOf(TrustDomain.of("other-domain.org"));

        assertFalse(isMemberOf);
    }

    @Test
    void test_exceedsMaximumSpiffeIdLength() {
        val path = StringUtils.repeat("a", 2028);
        val spiffeIdString = String.format("spiffe://example.org/%s", path);

        try {
            SpiffeId.parse(spiffeIdString);
            fail("Expected maximum length validation error");
        } catch (IllegalArgumentException e) {
            assertEquals("SPIFFE ID: maximum length is 2048 bytes", e.getMessage());
        }

        try {
            val trustDomain = TrustDomain.of("example.org");
            SpiffeId.of(trustDomain, path);
            fail("Expected maximum length validation error");
        } catch (IllegalArgumentException e) {
            assertEquals("SPIFFE ID: maximum length is 2048 bytes", e.getMessage());
        }
    }

    @Test
    void test_MaximumSpiffeIdLength() {
        val path = StringUtils.repeat("a", 2027);
        val spiffeIdString = String.format("spiffe://example.org/%s", path);

        try {
            SpiffeId.parse(spiffeIdString);

            val trustDomain = TrustDomain.of("example.org");
            SpiffeId.of(trustDomain, path);
        } catch (Exception e) {
            fail(e);
        }
    }
}
