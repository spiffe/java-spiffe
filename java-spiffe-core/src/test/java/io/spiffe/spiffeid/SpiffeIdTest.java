package io.spiffe.spiffeid;

import lombok.val;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

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
    void parse_aStringContainingInvalidSchema_throwsIllegalArgumentException() {
        val invalidadSpiffeId = "siffe://trust-domain.org/path1/path2";

        try {
            SpiffeId.parse(invalidadSpiffeId);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertEquals("Invalid SPIFFE schema", e.getMessage());
        }
    }

    @Test
    void parse_aBlankString_throwsIllegalArgumentException() {
        try {
            SpiffeId.parse("");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertEquals("SPIFFE ID cannot be empty", e.getMessage());
        }
    }

    @Test
    void parse_Null_throwsIllegalArgumentException() {
        try {
            SpiffeId.parse(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (NullPointerException e) {
            assertEquals("spiffeIdAsString is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void of_nullTrustDomain_throwsNullPointerException() {
        try {
            SpiffeId.of(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (NullPointerException e) {
            assertEquals("trustDomain is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void of_nullTrustDomainNotNullPath_throwsIllegalArgumentException() {
        try {
            SpiffeId.of(null, "path");
            fail("Should have thrown IllegalArgumentException");
        } catch (NullPointerException e) {
            assertEquals("trustDomain is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void equals_twoSpiffeIdsWithSameTrustDomainAndPath_returnsTrue() {
        val spiffeId1 = SpiffeId.of(TrustDomain.of("example.org"), "path1");
        val spiffeId2 = SpiffeId.of(TrustDomain.of("example.org"), "path1");

        assertEquals(spiffeId1, spiffeId2);
    }

    @Test
    void equals_twoSpiffeIdsWithSameTrustDomainAndDifferentPath_returnsFalse() {
        val spiffeId1 = SpiffeId.of(TrustDomain.of("example.org"), "path1");
        val spiffeId2 = SpiffeId.of(TrustDomain.of("example.org"), "other");

        assertNotEquals(spiffeId1, spiffeId2);
    }

    @Test
    void equals_twoSpiffeIdsWithDifferentTrustDomainAndSamePath_returnsFalse() {
        val spiffeId1 = SpiffeId.of(TrustDomain.of("example.org"), "path1");
        val spiffeId2 = SpiffeId.of(TrustDomain.of("other.org"), "path1");

        assertNotEquals(spiffeId1, spiffeId2);
    }
}
