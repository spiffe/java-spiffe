package io.spiffe.spiffeid;

import lombok.val;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static io.spiffe.utils.TestUtils.getLongString;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SpiffeIdTest {

    @Test
    void of_TrustDomainAndPathSegments_ReturnsSpiffeIdWithTrustDomainAndPathWithSegments() {
        val trustDomain = TrustDomain.of("trust-domain.org");

        val spiffeId = SpiffeId.of(trustDomain, "path1", "path2");

        assertAll("spiffeId",
                () -> assertEquals("trust-domain.org", spiffeId.getTrustDomain().toString()),
                () -> assertEquals("/path1/path2", spiffeId.getPath())
        );
    }

    @Test
    void of_TrustDomainAndNoPaths_ReturnsSpiffeIdWithTrustDomain() {
        val trustDomain = TrustDomain.of("trust-domain.org");

        val spiffeId = SpiffeId.of(trustDomain);

        assertAll("spiffeId",
                () -> assertEquals("trust-domain.org", spiffeId.getTrustDomain().toString()),
                () -> assertEquals("", spiffeId.getPath())
        );
    }

    @Test
    void of_TrustDomainAndPathsWithCaps_ReturnsSpiffeIdNormalized() {
        val trustDomain = TrustDomain.of("TRuST-DoMAIN.Org");

        val spiffeId = SpiffeId.of(trustDomain, "PATH1", "paTH2");

        assertAll("normalized spiffeId",
                () -> assertEquals("trust-domain.org", spiffeId.getTrustDomain().toString()),
                () -> assertEquals("/path1/path2", spiffeId.getPath())
        );
    }

    @Test
    void of_TrustDomainAndPathWithLeadingAndTrailingBlanks_ReturnsSpiffeIdNormalized() {
        val trustDomain = TrustDomain.of(" trust-domain.org ");

        val spiffeId = SpiffeId.of(trustDomain, " path1 ", " path2 ");

        assertAll("normalized spiffeId",
                () -> assertEquals("trust-domain.org", spiffeId.getTrustDomain().toString()),
                () -> assertEquals("/path1/path2", spiffeId.getPath())
        );
    }

    @Test
    void toString_SpiffeId_ReturnsTheSpiffeIdInAStringFormatIncludingTheSchema() {
        val trustDomain = TrustDomain.of("trust-domain.org");
        val spiffeId = SpiffeId.of(trustDomain, "path1", "path2", "path3");

        val spiffeIdToString = spiffeId.toString();

        assertEquals("spiffe://trust-domain.org/path1/path2/path3", spiffeIdToString);
    }

    @Test
    void memberOf_aTrustDomainAndASpiffeIdWithSameTrustDomain_ReturnTrue() {
        val trustDomain = TrustDomain.of("trust-domain.org");
        val spiffeId = SpiffeId.of(trustDomain, "path1", "path2");

        val isMemberOf = spiffeId.memberOf(TrustDomain.of("trust-domain.org"));

        assertTrue(isMemberOf);
    }

    @Test
    void memberOf_aTrustDomainAndASpiffeIdWithDifferentTrustDomain_ReturnFalse() {
        val trustDomain = TrustDomain.of("trust-domain.org");
        val spiffeId = SpiffeId.of(trustDomain, "path1", "path2");

        val isMemberOf = spiffeId.memberOf(TrustDomain.of("other-domain.org"));

        assertFalse(isMemberOf);
    }

    @Test
    void parse_aString_ReturnsASpiffeIdThatHasTrustDomainAndPathSegments() {
        val spiffeIdAsString = "spiffe://trust-domain.org/path1/path2";

        val spiffeId = SpiffeId.parse(spiffeIdAsString);

        assertAll("SpiffeId",
                () -> assertEquals("trust-domain.org", spiffeId.getTrustDomain().toString()),
                () -> assertEquals("/path1/path2", spiffeId.getPath())
        );
    }

    @Test
    void parse_aStringContainingLeadingAndTrailingBlanks_ReturnsASpiffeIdThatHasTrustDomainAndPathSegments() {
        val spiffeIdAsString = " spiffe://trust-domain.org/path1/path2 ";

        val spiffeId = SpiffeId.parse(spiffeIdAsString);

        assertAll("SpiffeId",
                () -> assertEquals("trust-domain.org", spiffeId.getTrustDomain().toString()),
                () -> assertEquals("/path1/path2", spiffeId.getPath())
        );
    }

    @Test
    void parse_pathWithColons() {
        val spiffeIdAsString = " spiffe://domain.test/pa:th/element: ";

        val spiffeId = SpiffeId.parse(spiffeIdAsString);

        assertAll("SpiffeId",
                () -> assertEquals("domain.test", spiffeId.getTrustDomain().toString()),
                () -> assertEquals("/pa:th/element:", spiffeId.getPath())
        );
    }

    @Test
    void parse_pathWithAt() {
        val spiffeIdAsString = "spiffe://domain.test/pa@th/element:";

        val spiffeId = SpiffeId.parse(spiffeIdAsString);

        assertAll("SpiffeId",
                () -> assertEquals("domain.test", spiffeId.getTrustDomain().toString()),
                () -> assertEquals("/pa@th/element:", spiffeId.getPath())
        );
    }

    @Test
    void parse_pathHasEncodedSubdelims() {
        val spiffeIdAsString = "spiffe://domain.test/p!a$t&h'/(e)l*e+m,e;n=t";

        val spiffeId = SpiffeId.parse(spiffeIdAsString);

        assertAll("SpiffeId",
                () -> assertEquals("domain.test", spiffeId.getTrustDomain().toString()),
                () -> assertEquals("/p!a$t&h'/(e)l*e+m,e;n=t", spiffeId.getPath())
        );
    }

    @Test
    void parse_spiffeId_maxLength() {
        val path = "/" + getLongString(2027);
        val spiffeIdAsString = "spiffe://domain.test" + path;

        val spiffeId = SpiffeId.parse(spiffeIdAsString);

        assertAll("SpiffeId",
                () -> assertEquals("domain.test", spiffeId.getTrustDomain().toString()),
                () -> assertEquals(path, spiffeId.getPath())
        );
    }

    @ParameterizedTest
    @MethodSource("provideTestInvalidSpiffeIds")
    void testParseTrustDomain(String input, Object expected) {
        SpiffeId result;
        try {
            result = SpiffeId.parse(input);
            assertEquals(expected, result.toString());
        } catch (Exception e) {
            assertEquals(expected, e.getMessage());
        }
    }

    static Stream<Arguments> provideTestInvalidSpiffeIds() {
        return Stream.of(
                Arguments.of("", "SPIFFE ID cannot be empty"),
                Arguments.of("192.168.2.2:6688", "Illegal character in scheme name at index 0: 192.168.2.2:6688"),
                Arguments.of("http://domain.test/path/element", "SPIFFE ID: invalid scheme"),
                Arguments.of("spiffe:///path/element", "SPIFFE ID: trust domain is empty"),
                Arguments.of("spiffe://domain.test/path/element?query=1", "SPIFFE ID: query is not allowed"),
                Arguments.of("spiffe://domain.test/path/element?#fragment-1", "SPIFFE ID: fragment is not allowed"),
                Arguments.of("spiffe://domain.test:8080/path/element", "SPIFFE ID: port is not allowed"),
                Arguments.of("spiffe://user:password@test.org/path/element", "SPIFFE ID: user info is not allowed"),
                Arguments.of("spiffe:path/element", "SPIFFE ID: trust domain is empty"),
                Arguments.of("spiffe:/path/element", "SPIFFE ID: trust domain is empty"),
                Arguments.of("spiffe://domain.test/path/elem%5uent", "Malformed escape pair at index 30: spiffe://domain.test/path/elem%5uent"),
                Arguments.of("spiffe://domain.test/"+getLongString(2028), "SPIFFE ID: too long, maximum is 2048 bytes")
        );
    }

}
