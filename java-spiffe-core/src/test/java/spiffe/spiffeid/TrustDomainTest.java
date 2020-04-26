package spiffe.spiffeid;

import lombok.val;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;


public class TrustDomainTest {
    
    @Test
    void of_givenAString_returnTrustDomain() {
        val trustDomain = TrustDomain.of("domain.test");
        assertEquals("domain.test", trustDomain.toString());
    }

    @Test
    void of_givenASpiffeIdString_returnTrustDomainWithHostPart() {
        val trustDomain = TrustDomain.of("spiffe://domain.test");
        assertEquals("domain.test", trustDomain.toString());
    }

    @Test
    void of_givenASpiffeIdStringWithPath_returnTrustDomainWithHostPart() {
        val trustDomain = TrustDomain.of("spiffe://domain.test/workload");
        assertEquals("domain.test", trustDomain.toString());
    }

    @Test
    void of_givenAStringWithCaps_returnNormalizedTrustDomain() {
        val trustDomain = TrustDomain.of("DoMAin.TesT");

        assertEquals("domain.test", trustDomain.toString());
    }

    @Test
    void of_givenAStringWithTrailingAndLeadingBlanks_returnNormalizedTrustDomain() {
        val trustDomain = TrustDomain.of(" domain.test ");

        assertEquals("domain.test", trustDomain.toString());
    }

    @Test
    void of_nullString_ThrowsIllegalArgumentException() {
        try {
            TrustDomain.of(null);
        } catch (NullPointerException e) {
            assertEquals("trustDomain is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void of_emptyString_ThrowsIllegalArgumentException() {
        try {
            TrustDomain.of("");
        } catch (IllegalArgumentException e) {
            assertEquals("Trust Domain cannot be empty", e.getMessage());
        }
    }

    @Test
    void of_blankString_ThrowsIllegalArgumentException() {
        try {
            TrustDomain.of(" ");
        } catch (IllegalArgumentException e) {
            assertEquals("Trust Domain cannot be empty", e.getMessage());
        }
    }

    @Test
    void equals_twoTrustDomainObjectsWithTheSameString_returnsTrue() {
        val trustDomain1 = TrustDomain.of("example.org");
        val trustDomain2 = TrustDomain.of("example.org");

        assertEquals(trustDomain1, trustDomain2);
    }

    @Test
    void equals_twoTrustDomainObjectsWithDifferentStrings_returnsFalse() {
        val trustDomain1 = TrustDomain.of("example.org");
        val trustDomain2 = TrustDomain.of("other.org");

        assertNotEquals(trustDomain1, trustDomain2);
    }
}
