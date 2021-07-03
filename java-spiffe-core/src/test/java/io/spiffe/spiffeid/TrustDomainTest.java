package io.spiffe.spiffeid;

import io.spiffe.exception.InvalidSpiffeIdException;
import lombok.val;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static io.spiffe.spiffeid.SpiffeIdTest.TD_CHARS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

class TrustDomainTest {


    @Test
    void testTrustDomainFromName() {
        TrustDomain trustDomain = TrustDomain.parse("trustdomain");
        assertEquals("trustdomain", trustDomain.getName());
    }

    @Test
    void testFromIdStringWithoutPath() {
        TrustDomain trustDomain = TrustDomain.parse("spiffe://trustdomain");
        assertEquals("trustdomain", trustDomain.getName());
    }

    @Test
    void testFromIdStringWithPath() {
        TrustDomain trustDomain = TrustDomain.parse("spiffe://trustdomain/path");
        assertEquals("trustdomain", trustDomain.getName());
    }

    @Test
    void testAllChars() {
        // Go all the way through 255, which ensures we reject UTF-8 appropriately
        for (int i = 0; i < 256; i++) {
            char c = (char) i;
            String td = "trustdomain" + c;

            if (TD_CHARS.contains(c)) {
                TrustDomain trustDomain = TrustDomain.parse(td);
                assertEquals(td, trustDomain.getName());
            } else {
                try {
                    TrustDomain.parse(td);
                } catch (InvalidSpiffeIdException e) {
                    assertEquals(e.getMessage(), "Trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores");
                }
            }
        }
    }

    @ParameterizedTest
    @MethodSource("provideInvalidTrustDomain")
    void testParseTrustDomain(String input, Object expected) {
        TrustDomain result;
        try {
            TrustDomain.parse(input);
            fail("error expected");
        } catch (Exception e) {
            assertEquals(expected, e.getMessage().trim());
        }
    }

    static Stream<Arguments> provideInvalidTrustDomain() {
        return Stream.of(
                Arguments.of("", "Trust domain is missing"),
                Arguments.of("spiffe://", "Trust domain is missing"),
                Arguments.of(null, "idOrName is marked non-null but is null"),
                Arguments.of("Trustdomain", "Trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores"),
                Arguments.of("spiffe://Domain.test", "Trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores"),
                Arguments.of("spiffe://domain.test/spiffe://domain.test/path/element", "Path segment characters are limited to letters, numbers, dots, dashes, and underscores"),
                Arguments.of("http://domain.test", "Scheme is missing or invalid"),
                Arguments.of("spiffe:// domain.test ", "Trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores"),
                Arguments.of("://domain.test", "Scheme is missing or invalid"),
                Arguments.of("spiffe:///path/element", "Trust domain is missing"),
                Arguments.of("/path/element", "Trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores"),
                Arguments.of("spiffe://domain.test:80", "Trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores"),
                Arguments.of("spiffe:/trustdomain/path", "Scheme is missing or invalid"),
                Arguments.of("spiffe://trustdomain/", "Path cannot have a trailing slash"),
                Arguments.of("spiffe://trustdomain/path/", "Path cannot have a trailing slash")
        );
    }

    @Test
    void testNewSpiffeId() {
        TrustDomain trustDomain = TrustDomain.parse("test.domain");
        SpiffeId spiffeId = trustDomain.newSpiffeId("/path1", "/host");

        assertEquals(trustDomain, spiffeId.getTrustDomain());
        assertEquals("/path1/host", spiffeId.getPath());
    }

    @Test
    void testToString() {
        TrustDomain trustDomain = TrustDomain.parse("test.domain");
        assertEquals("test.domain", trustDomain.toString());
    }

    @Test
    void test_toIdString() {
        val trustDomain = TrustDomain.parse("domain.test");
        assertEquals("spiffe://domain.test", trustDomain.toIdString());
    }
}
