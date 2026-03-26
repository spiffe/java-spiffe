package io.spiffe.spiffeid;

import com.google.common.collect.Sets;
import io.spiffe.exception.InvalidSpiffeIdException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class SpiffeIdTest {
    private static final Set<Character> LOWER_ALPHA = Sets.newHashSet('a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z');
    private static final Set<Character> UPPER_ALPHA = Sets.newHashSet('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z');
    private static final Set<Character> NUMBERS = Sets.newHashSet('0', '1', '2', '3', '4', '5', '6', '7', '8', '9');
    private static final Set<Character> SPECIAL_CHARS = Sets.newHashSet('.', '-', '_');

    static final Set<Character> TD_CHARS = Stream.of(
            LOWER_ALPHA,
            NUMBERS,
            SPECIAL_CHARS)
            .flatMap(Set::stream)
            .collect(Collectors.toSet());

    static final Set<Character> PATH_CHARS = Stream.of(
            LOWER_ALPHA,
            UPPER_ALPHA,
            NUMBERS,
            SPECIAL_CHARS)
            .flatMap(Set::stream)
            .collect(Collectors.toSet());

    @Test
    void toString_SpiffeId_ReturnsTheSpiffeIdInAStringFormatIncludingTheSchema() {
        TrustDomain trustDomain = TrustDomain.parse("trustdomain");
        SpiffeId spiffeId = SpiffeId.fromSegments(trustDomain, "path1", "path2", "path3");
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
                Arguments.of("spiffe://trustdomain/9eebccd2-12bf-40a6-b262-65fe0487d453", TrustDomain.parse("trustdomain"), "/9eebccd2-12bf-40a6-b262-65fe0487d453"),
                Arguments.of("spiffe://a_b.example/foo", TrustDomain.parse("a_b.example"), "/foo"),
                Arguments.of("spiffe://1.2.3.4/service", TrustDomain.parse("1.2.3.4"), "/service"),
                Arguments.of("SPIFFE://trustdomain/path", TrustDomain.parse("trustdomain"), "/path"),
                Arguments.of("SpIfFe://TrUsTdOmAiN/Workload", TrustDomain.parse("trustdomain"), "/Workload")
        );
    }

    static Stream<String> provideNonDnsShapedTrustDomains() {
        return Stream.of(
                "example..org",
                ".example.org",
                "example.org.",
                "-example.org",
                "example-.org"
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
                Arguments.of("spiffe://", "Trust domain is missing"),
                Arguments.of("spiffe://domain.test/path/elem%5uent", "Path segment characters are limited to letters, numbers, dots, dashes, and underscores"),
                Arguments.of("spiffe://trustdomain/path//", "Path cannot contain empty segments"),
                Arguments.of("spiffe://trustdomain/./other", "Path cannot contain dot segments"),
                Arguments.of("spiffe://trustdomain/../other", "Path cannot contain dot segments"),
                Arguments.of("spiffe://trustdomain/", "Path cannot have a trailing slash"),
                Arguments.of("spiffe://trustdomain/path/", "Path cannot have a trailing slash"),
                Arguments.of("spiffe://[::1]/service", "Trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores"),
                Arguments.of("spiffe://[2001:db8::1]/service", "Trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores"),
                Arguments.of("xspiffe://trustdomain/path", "Scheme is missing or invalid")
        );
    }

    @ParameterizedTest
    @MethodSource("provideValidTrustDomainAndPaths")
    void testOf(TrustDomain inputTrustDomain, String[] inputPath, SpiffeId expectedSpiffeId) {
        try {
            SpiffeId result = SpiffeId.fromSegments(inputTrustDomain, inputPath);
            assertEquals(expectedSpiffeId, result);
        } catch (Exception e) {
            fail("Unexpected error", e);
        }
    }

    static Stream<Arguments> provideValidTrustDomainAndPaths() {
        return Stream.of(
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{"path"}, SpiffeId.parse("spiffe://trustdomain/path")),
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{"path1", "path2"}, SpiffeId.parse("spiffe://trustdomain/path1/path2")),
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{"PATH1", "PATH2"}, SpiffeId.parse("spiffe://trustdomain/PATH1/PATH2")),
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{"path1", "path2"}, SpiffeId.parse("spiffe://trustdomain/path1/path2")),
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{"9eebccd2-12bf-40a6-b262-65fe0487d453"}, SpiffeId.parse("spiffe://trustdomain/9eebccd2-12bf-40a6-b262-65fe0487d453"))
        );
    }

    @ParameterizedTest
    @MethodSource("provideInvalidArguments")
    void testOfInvalid(TrustDomain trustDomain, String[] inputPath, String expectedError) {
        try {
            SpiffeId.fromSegments(trustDomain, inputPath);
            fail(String.format("Expected error %s", expectedError));
        } catch (Exception e) {
            assertEquals(expectedError, e.getMessage());
        }
    }

    static Stream<Arguments> provideInvalidArguments() {
        return Stream.of(
                Arguments.of(null, new String[]{""}, "trustDomain must not be null"),
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{""}, "Cannot be empty"),
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{"ele%5ment"}, "Path segment characters are limited to letters, numbers, dots, dashes, and underscores"),
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{"/service"}, "Path segment characters are limited to letters, numbers, dots, dashes, and underscores"),
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{"service/"}, "Path segment characters are limited to letters, numbers, dots, dashes, and underscores"),
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{"foo/bar"}, "Path segment characters are limited to letters, numbers, dots, dashes, and underscores"),
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{"."}, "Path cannot contain dot segments"),
                Arguments.of(TrustDomain.parse("trustdomain"), new String[]{".."}, "Path cannot contain dot segments")
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
            String path = "/path" + c;

            if (PATH_CHARS.contains(c)) {
                SpiffeId spiffeId = SpiffeId.parse("spiffe://trustdomain" + path);
                assertEquals(spiffeId.toString(), "spiffe://trustdomain" + path);
            } else {
                try {
                    SpiffeId.parse("spiffe://trustdomain" + path);
                } catch (InvalidSpiffeIdException e) {
                    assertEquals("Path segment characters are limited to letters, numbers, dots, dashes, and underscores", e.getMessage());
                }
            }

            String td = "spiffe://trustdomain" + c;

            char normalizedTdChar = Character.toLowerCase(c);
            if (TrustDomain.isValidTrustDomainChar(normalizedTdChar)) {
                SpiffeId spiffeId = SpiffeId.parse(td);
                assertEquals("spiffe://trustdomain" + normalizedTdChar, spiffeId.toString());
            } else {
                try {
                    SpiffeId.parse(td);
                } catch (InvalidSpiffeIdException e) {
                    assertEquals("Trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores", e.getMessage());
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
            String path1 = "path1" + c;
            String path2 = "path2" + c;
            TrustDomain td = TrustDomain.parse("trustdomain");

            if (PATH_CHARS.contains(c)) {
                SpiffeId spiffeId = SpiffeId.fromSegments(td, path1, path2);
                assertEquals(spiffeId.toString(), String.format("spiffe://trustdomain/%s/%s", path1, path2));
            } else {
                try {
                    SpiffeId.fromSegments(td, path1, path2);
                } catch (InvalidSpiffeIdException e) {
                    assertEquals("Path segment characters are limited to letters, numbers, dots, dashes, and underscores", e.getMessage());
                }
            }
        }
    }

    @Test
    void memberOf_aTrustDomainAndASpiffeIdWithSameTrustDomain_ReturnsTrue() {
        TrustDomain trustDomain = TrustDomain.parse("trustdomain");
        SpiffeId spiffeId = SpiffeId.fromSegments(trustDomain, "path1", "path2");

        boolean isMemberOf;
        if (spiffeId.memberOf(TrustDomain.parse("trustdomain"))) isMemberOf = true;
        else isMemberOf = false;

        assertTrue(isMemberOf);
    }

    @Test
    void memberOf_aTrustDomainAndASpiffeIdWithDifferentTrustDomain_ReturnsFalse() {
        final TrustDomain trustDomain = TrustDomain.parse("trustdomain");
        final SpiffeId spiffeId = SpiffeId.fromSegments(trustDomain, "path1", "path2");

        boolean isMemberOf;
        if (spiffeId.memberOf(TrustDomain.parse("otherdomain"))) isMemberOf = true;
        else isMemberOf = false;

        assertFalse(isMemberOf);
    }

    @Test
    void parseMixedCaseSchemeAndTrustDomain_toStringReturnsCanonicalFormAndPreservesPathCase() {
        SpiffeId spiffeId = SpiffeId.parse("SPIFFE://EXAMPLE.ORG/MyService");

        assertEquals("spiffe://example.org/MyService", spiffeId.toString());
    }

    @Test
    void parseEquivalentIdsWithDifferentSchemeAndTrustDomainCase_areEqual() {
        SpiffeId lowercase = SpiffeId.parse("spiffe://example.org/service");
        SpiffeId uppercaseScheme = SpiffeId.parse("SPIFFE://example.org/service");
        SpiffeId uppercaseTrustDomain = SpiffeId.parse("spiffe://EXAMPLE.ORG/service");
        SpiffeId uppercaseBoth = SpiffeId.parse("SPIFFE://EXAMPLE.ORG/service");

        assertEquals(lowercase, uppercaseScheme);
        assertEquals(lowercase, uppercaseTrustDomain);
        assertEquals(lowercase, uppercaseBoth);
        assertEquals(lowercase.hashCode(), uppercaseBoth.hashCode());
    }

    @Test
    void parseIdsWithDifferentPathCase_areNotEqual() {
        SpiffeId lowercasePath = SpiffeId.parse("spiffe://example.org/service");
        SpiffeId uppercasePath = SpiffeId.parse("spiffe://example.org/Service");

        assertNotEquals(lowercasePath, uppercasePath);
    }

    @ParameterizedTest
    @MethodSource("provideNonDnsShapedTrustDomains")
    void parseSpiffeIdWithNonDnsShapedTrustDomain_isAccepted(String trustDomainName) {
        SpiffeId spiffeId = SpiffeId.parse("spiffe://" + trustDomainName + "/service");

        assertEquals(TrustDomain.parse(trustDomainName), spiffeId.getTrustDomain());
        assertEquals("/service", spiffeId.getPath());
        assertEquals("spiffe://" + trustDomainName + "/service", spiffeId.toString());
    }

    @ParameterizedTest
    @MethodSource("provideNonDnsShapedTrustDomains")
    void fromSegmentsWithNonDnsShapedTrustDomain_isAccepted(String trustDomainName) {
        TrustDomain trustDomain = TrustDomain.parse(trustDomainName);

        SpiffeId spiffeId = SpiffeId.fromSegments(trustDomain, "service");

        assertEquals(trustDomain, spiffeId.getTrustDomain());
        assertEquals("/service", spiffeId.getPath());
        assertEquals("spiffe://" + trustDomainName + "/service", spiffeId.toString());
    }

    @ParameterizedTest
    @MethodSource("provideInvalidSegmentsForFromSegments")
    void fromSegments_invalidSegment_throwsInvalidSpiffeIdException(String segment, String expectedMessage) {
        InvalidSpiffeIdException ex = assertThrows(
                InvalidSpiffeIdException.class,
                () -> SpiffeId.fromSegments(TrustDomain.parse("example.org"), segment));
        assertEquals(expectedMessage, ex.getMessage());
    }

    static Stream<Arguments> provideInvalidSegmentsForFromSegments() {
        return Stream.of(
                Arguments.of(null, SpiffeId.EMPTY),
                Arguments.of("", SpiffeId.EMPTY),
                Arguments.of(" ", SpiffeId.BAD_PATH_SEGMENT_CHAR)
        );
    }

    @ParameterizedTest
    @MethodSource("provideInvalidPathsForValidatePath")
    void validatePath_invalidPath_throwsInvalidSpiffeIdException(String path, String expectedMessage) {
        InvalidSpiffeIdException ex = assertThrows(
                InvalidSpiffeIdException.class,
                () -> SpiffeId.validatePath(path));
        assertEquals(expectedMessage, ex.getMessage());
    }

    static Stream<Arguments> provideInvalidPathsForValidatePath() {
        return Stream.of(
                Arguments.of("   ", SpiffeId.EMPTY),
                Arguments.of("foo", SpiffeId.MISSING_LEADING_SLASH),
                Arguments.of("foo/bar", SpiffeId.MISSING_LEADING_SLASH),
                Arguments.of("/foo//bar", SpiffeId.EMPTY_SEGMENT),
                Arguments.of("/./other", SpiffeId.DOT_SEGMENT),
                Arguments.of("/../other", SpiffeId.DOT_SEGMENT),
                Arguments.of("/foo/.", SpiffeId.DOT_SEGMENT),
                Arguments.of("/foo/..", SpiffeId.DOT_SEGMENT),
                Arguments.of("/foo/", SpiffeId.TRAILING_SLASH),
                Arguments.of("/", SpiffeId.TRAILING_SLASH),
                Arguments.of("/ ", SpiffeId.BAD_PATH_SEGMENT_CHAR),
                Arguments.of("/foo%5Cbar", SpiffeId.BAD_PATH_SEGMENT_CHAR),
                Arguments.of("/foo bar", SpiffeId.BAD_PATH_SEGMENT_CHAR)
        );
    }

    @ParameterizedTest
    @MethodSource("provideValidPathsForValidatePath")
    void validatePath_validPath_doesNotThrow(String path) {
        assertDoesNotThrow(() -> SpiffeId.validatePath(path));
    }

    static Stream<String> provideValidPathsForValidatePath() {
        return Stream.of(
                "/foo",
                "/foo/bar",
                "/PATH/path",
                "/.../svc",
                "/9eebccd2-12bf-40a6-b262-65fe0487d453"
        );
    }
}
