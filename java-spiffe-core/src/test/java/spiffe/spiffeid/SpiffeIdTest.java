package spiffe.spiffeid;

import lombok.val;
import org.junit.jupiter.api.Test;
import spiffe.result.Error;
import spiffe.result.Ok;

import static org.junit.jupiter.api.Assertions.*;

public class SpiffeIdTest {
    
    @Test
    void of_TrustDomainAndPathSegments_ReturnsSpiffeIdWithTrustDomainAndPathWithSegments() {
        val trustDomain = TrustDomain.of("trust-domain.org").getValue();

        val spiffeIdResult = SpiffeId.of(trustDomain, "path1", "path2");

        assertAll("spiffeId",
                () -> assertEquals("trust-domain.org", spiffeIdResult.getValue().getTrustDomain().toString()),
                () -> assertEquals("/path1/path2", spiffeIdResult.getValue().getPath())
        );
    }

    @Test
    void of_BlankPaths_ReturnsSpiffeIdWithTrustDomainAndPathWithSegments() {
        val trustDomain = TrustDomain.of("trust-domain.org").getValue();

        val spiffeIdResult = SpiffeId.of(trustDomain, "", "");

        assertAll("spiffeId",
                () -> assertEquals("trust-domain.org", spiffeIdResult.getValue().getTrustDomain().toString()),
                () -> assertEquals("", spiffeIdResult.getValue().getPath())
        );
    }

    @Test
    void of_TrustDomainAndPathsWithCaps_ReturnsSpiffeIdNormalized() {
        val trustDomain = TrustDomain.of("TRuST-DoMAIN.Org").getValue();

        val spiffeIdResult = SpiffeId.of(trustDomain, "PATH1", "paTH2");

        assertAll("normalized spiffeId",
                () -> assertEquals("trust-domain.org", spiffeIdResult.getValue().getTrustDomain().toString()),
                () -> assertEquals("/path1/path2", spiffeIdResult.getValue().getPath())
        );
    }

    @Test
    void of_TrustDomainAndPathWithLeadingAndTrailingBlanks_ReturnsSpiffeIdNormalized() {
        val trustDomain = TrustDomain.of(" trust-domain.org ").getValue();

        val spiffeIdResult = SpiffeId.of(trustDomain, " path1 ", " path2 ");

        assertAll("normalized spiffeId",
                () -> assertEquals("trust-domain.org", spiffeIdResult.getValue().getTrustDomain().toString()),
                () -> assertEquals("/path1/path2", spiffeIdResult.getValue().getPath())
        );
    }

    @Test
    void toString_SpiffeId_ReturnsTheSpiffeIdInAStringFormatIncludingTheSchema() {
        val trustDomain = TrustDomain.of("trust-domain.org").getValue();
        val spiffeId = SpiffeId.of(trustDomain, "path1", "path2", "path3").getValue();

        val spiffeIdToString = spiffeId.toString();

        assertEquals("spiffe://trust-domain.org/path1/path2/path3", spiffeIdToString);
    }

    @Test
    void memberOf_aTrustDomainAndASpiffeIdWithSameTrustDomain_ReturnTrue() {
        val trustDomain = TrustDomain.of("trust-domain.org").getValue();
        val spiffeId = SpiffeId.of(trustDomain, "path1", "path2").getValue();

        val isMemberOf = spiffeId.memberOf(TrustDomain.of("trust-domain.org").getValue());

        assertTrue(isMemberOf);
    }

    @Test
    void memberOf_aTrustDomainAndASpiffeIdWithDifferentTrustDomain_ReturnFalse() {
        val trustDomain = TrustDomain.of("trust-domain.org").getValue();
        val spiffeId = SpiffeId.of(trustDomain, "path1", "path2").getValue();

        val isMemberOf = spiffeId.memberOf(TrustDomain.of("other-domain.org").getValue());

        assertFalse(isMemberOf);
    }

    @Test
    void parse_aString_ReturnsASpiffeIdThatHasTrustDomainAndPathSegments() {
        val spiffeIdAsString = "spiffe://trust-domain.org/path1/path2";

        val spiffeIdResult = SpiffeId.parse(spiffeIdAsString);

        assertAll("SpiffeId",
                () -> assertEquals(Ok.class, spiffeIdResult.getClass()),
                () -> assertEquals("trust-domain.org", spiffeIdResult.getValue().getTrustDomain().toString()),
                () -> assertEquals("/path1/path2", spiffeIdResult.getValue().getPath())
        );

    }

    @Test
    void parse_aStringContainingInvalidSchema_ReturnsError() {
        val invalidadSpiffeId = "siffe://trust-domain.org/path1/path2";

        val spiffeIdResult = SpiffeId.parse(invalidadSpiffeId);

        assertAll("Error",
                () -> assertEquals(Error.class, spiffeIdResult.getClass()),
                () -> assertEquals("Invalid SPIFFE schema", spiffeIdResult.getError())
        );

    }

    @Test
    void parse_aBlankString_ReturnsAError() {
        val spiffeIdAsString = "";

        val spiffeIdResult = SpiffeId.parse(spiffeIdAsString);

        assertAll("Error",
                () -> assertEquals(Error.class, spiffeIdResult.getClass()),
                () -> assertEquals("SPIFFE ID cannot be empty", spiffeIdResult.getError())
        );
    }

    @Test
    void of_nullTrustDomain_returnsAError() {
        val spiffeIdResult = SpiffeId.of(null, "path");

        assertEquals(Error.class, spiffeIdResult.getClass());
        assertEquals("Trust Domain cannot be null", spiffeIdResult.getError());
    }

    @Test
    void equals_twoSpiffeIdsWithSameTrustDomainAndPath_returnsTrue() {
        val spiffeId1 = SpiffeId.of(TrustDomain.of("example.org").getValue(), "path1").getValue();
        val spiffeId2 = SpiffeId.of(TrustDomain.of("example.org").getValue(), "path1").getValue();

        assertEquals(spiffeId1, spiffeId2);
    }

    @Test
    void equals_twoSpiffeIdsWithSameTrustDomainAndDifferentPath_returnsFalse() {
        val spiffeId1 = SpiffeId.of(TrustDomain.of("example.org").getValue(), "path1").getValue();
        val spiffeId2 = SpiffeId.of(TrustDomain.of("example.org").getValue(), "other").getValue();

        assertNotEquals(spiffeId1, spiffeId2);
    }

    @Test
    void equals_twoSpiffeIdsWithDifferentTrustDomainAndSamePath_returnsFalse() {
        val spiffeId1 = SpiffeId.of(TrustDomain.of("example.org").getValue(), "path1").getValue();
        val spiffeId2 = SpiffeId.of(TrustDomain.of("other.org").getValue(), "path1").getValue();

        assertNotEquals(spiffeId1, spiffeId2);
    }
}
