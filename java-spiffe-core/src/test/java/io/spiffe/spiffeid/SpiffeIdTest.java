package io.spiffe.spiffeid;

import com.google.common.collect.Sets;
import io.spiffe.exception.InvalidSpiffeIdException;
import lombok.val;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class SpiffeIdTest {

    static final Set<Character> TD_CHARS = Sets.newHashSet(
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            '.', '-', '_'
    );

    static final Set<Character> PATH_CHARS = Sets.newHashSet(
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            '.', '-', '_'
    );


    @Test
    void toString_SpiffeId_ReturnsTheSpiffeIdInAStringFormatIncludingTheSchema() {
        val trustDomain = TrustDomain.parse("trustdomain");
        val spiffeId = SpiffeId.of(trustDomain, "/path1", "/path2", "/path3");
        assertEquals("spiffe://trustdomain/path1/path2/path3", spiffeId.toString());
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
                Arguments.of("spiffe://trustdomain", TrustDomain.parse("trustdomain"), ""),
                Arguments.of("spiffe://trustdomain/path", TrustDomain.parse("trustdomain"), "/path"),
                Arguments.of("spiffe://trustdomain/path1/path2", TrustDomain.parse("trustdomain"), "/path1/path2"),
                Arguments.of("spiffe://trustdomain/PATH1/PATH2", TrustDomain.parse("trustdomain"), "/PATH1/PATH2"),
                Arguments.of("spiffe://trustdomain/9eebccd2-12bf-40a6-b262-65fe0487d453", TrustDomain.parse("trustdomain"), "/9eebccd2-12bf-40a6-b262-65fe0487d453")
        );
    }

    @ParameterizedTest
    @MethodSource("provideInvalidSpiffeIds")
    void testParseInvalidSpiffeId(String input, String expected) {
        try {
            SpiffeId.parse(input);
            fail("Expected validation SPIFFE ID error");
        } catch (Exception e) {
            assertEquals(expected, e.getMessage());
        }
    }

    static Stream<Arguments> provideInvalidSpiffeIds() {
        return Stream.of(
                Arguments.of("", "Cannot be empty"),
                Arguments.of(null, "Cannot be empty"),
                Arguments.of("192.168.2.2:6688", "Scheme is missing or invalid"),
                Arguments.of("http://domain.test/path/element", "Scheme is missing or invalid"),
                Arguments.of("spiffe:///path/element", "Trust domain is missing"),
                Arguments.of("spiffe://domain.test/path/element?query=1", "Path segment characters are limited to letters, numbers, dots, dashes, and underscores"),
                Arguments.of("spiffe://domain.test/path/element?#fragment-1", "Path segment characters are limited to letters, numbers, dots, dashes, and underscores"),
                Arguments.of("spiffe://domain.test:8080/path/element", "Trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores"),
                Arguments.of("spiffe://user:password@test.org/path/element", "Trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores"),
                Arguments.of("spiffe:path/element", "Scheme is missing or invalid"),
                Arguments.of("spiffe:/path/element", "Scheme is missing or invalid"),
                Arguments.of("SPIFFE://path/element", "Scheme is missing or invalid"),
                Arguments.of("spiffe://domain.test/path/elem%5uent", "Path segment characters are limited to letters, numbers, dots, dashes, and underscores"),
                Arguments.of("spiffe://trustdomain/path//", "Path cannot contain empty segments"),
                Arguments.of("spiffe://trustdomain/./other", "Path cannot contain dot segments"),
                Arguments.of("spiffe://trustdomain/../other", "Path cannot contain dot segments"),
                Arguments.of("spiffe://trustdomain/", "Path cannot have a trailing slash"),
                Arguments.of("spiffe://trustdomain/path/", "Path cannot have a trailing slash")
        );
    }

    @ParameterizedTest
    @MethodSource("provideValidTrustDomainAndPaths")
    void testOf(TrustDomain inputTrustDomain, String[] inputPath, SpiffeId expectedSpiffeId) {
        try {
            SpiffeId result = SpiffeId.of(inputTrustDomain, inputPath);
            assertEquals(result, expectedSpiffeId);
        } catch (Exception e) {
            fail("Unexpected error", e);
        }
    }

    static Stream<Arguments> provideValidTrustDomainAndPaths() {
        return Stream.of(
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{""}, SpiffeId.parse("spiffe://trustdomain")),
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{"/path"}, SpiffeId.parse("spiffe://trustdomain/path")),
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{"/path1", "/path2"}, SpiffeId.parse("spiffe://trustdomain/path1/path2")),
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{"/PATH1", "/PATH2"}, SpiffeId.parse("spiffe://trustdomain/PATH1/PATH2")),
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{"/path1", "/path2"}, SpiffeId.parse("spiffe://trustdomain/path1/path2")),
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{"/9eebccd2-12bf-40a6-b262-65fe0487d453"}, SpiffeId.parse("spiffe://trustdomain/9eebccd2-12bf-40a6-b262-65fe0487d453"))
        );
    }

    @ParameterizedTest
    @MethodSource("provideInvalidArguments")
    void testOfInvalid(TrustDomain trustDomain, String[] inputPath, String expectedError) {
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
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{"element"}, "Path must have a leading slash"),
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{"/ele%5ment"}, "Path segment characters are limited to letters, numbers, dots, dashes, and underscores"),
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{"/path/"}, "Path cannot have a trailing slash"),
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{"/ /"}, "Path segment characters are limited to letters, numbers, dots, dashes, and underscores"),
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{"/"}, "Path cannot have a trailing slash"),
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{"//"}, "Path cannot contain empty segments"),
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{"/./"}, "Path cannot contain dot segments"),
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{"/../"}, "Path cannot contain dot segments")
        );
    }

    @Test
    void testParseWithAllChars() {
        // Go all the way through 255, which ensures we reject UTF-8 appropriately
        for (int i = 0; i < 256; i++) {
            char c = (char) i;

            // Don't test '/' since it is the delimiter between path segments
            if (c == '/') {
                continue;
            }
            String path = "/path"+ c;

            if (PATH_CHARS.contains(c)) {
                SpiffeId spiffeId = SpiffeId.parse("spiffe://trustdomain" + path);
                assertEquals(spiffeId.toString(), "spiffe://trustdomain" + path);
            } else {
                try {
                    SpiffeId.parse("spiffe://trustdomain" + path);
                } catch (InvalidSpiffeIdException e) {
                    assertEquals(e.getMessage(), "Path segment characters are limited to letters, numbers, dots, dashes, and underscores");
                }
            }

            String td = "spiffe://trustdomain" + c;

            if (TD_CHARS.contains(c)) {
                SpiffeId spiffeId = SpiffeId.parse(td);
                assertEquals(spiffeId.toString(), td);
            } else {
                try {
                    SpiffeId.parse(td);
                } catch (InvalidSpiffeIdException e) {
                    assertEquals(e.getMessage(), "Trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores");
                }
            }
        }
    }

    @Test
    void testOfWithAllChars() {
        // Go all the way through 255, which ensures we reject UTF-8 appropriately
        for (int i = 0; i < 256; i++) {
            char c = (char) i;

            // Don't test '/' since it is the delimiter between path segments
            if (c == '/') {
                continue;
            }
            String path1 = "/path1"+ c;
            String path2 = "/path2"+ c;
            TrustDomain td = TrustDomain.parse("trustdomain");

            if (PATH_CHARS.contains(c)) {
                SpiffeId spiffeId = SpiffeId.of(td, path1, path2);
                assertEquals(spiffeId.toString(), "spiffe://trustdomain" + path1 + path2);
            } else {
                try {
                    SpiffeId.of(td, path1, path2);
                } catch (InvalidSpiffeIdException e) {
                    assertEquals(e.getMessage(), "Path segment characters are limited to letters, numbers, dots, dashes, and underscores");
                }
            }
        }
    }

    @Test
    void memberOf_aTrustDomainAndASpiffeIdWithSameTrustDomain_ReturnsTrue() {
        val trustDomain = TrustDomain.parse("trustdomain");
        val spiffeId = SpiffeId.of(trustDomain, "/path1", "/path2");

        val isMemberOf = spiffeId.memberOf(TrustDomain.parse("trustdomain"));

        assertTrue(isMemberOf);
    }

    @Test
    void memberOf_aTrustDomainAndASpiffeIdWithDifferentTrustDomain_ReturnsFalse() {
        val trustDomain = TrustDomain.parse("trustdomain");
        val spiffeId = SpiffeId.of(trustDomain, "/path1", "/path2");

        val isMemberOf = spiffeId.memberOf(TrustDomain.parse("otherdomain"));

        assertFalse(isMemberOf);
    }
}
