package spiffe.spiffeid;

import lombok.val;
import org.junit.jupiter.api.Test;
import spiffe.result.Error;

import static org.junit.jupiter.api.Assertions.*;


public class TrustDomainTest {
    
    @Test
    void of_givenAString_returnTrustDomain() {
        val trustDomainResult = TrustDomain.of("domain.test");
        assertEquals("domain.test", trustDomainResult.getValue().toString());
    }

    @Test
    void of_givenASpiffeIdString_returnTrustDomainWithHostPart() {
        val trustDomainResult = TrustDomain.of("spiffe://domain.test");
        assertEquals("domain.test", trustDomainResult.getValue().toString());
    }

    @Test
    void of_givenASpiffeIdStringWithPath_returnTrustDomainWithHostPart() {
        val trustDomainResult = TrustDomain.of("spiffe://domain.test/workload");
        assertEquals("domain.test", trustDomainResult.getValue().toString());
    }

    @Test
    void of_givenAStringWithCaps_returnNormalizedTrustDomain() {
        val trustDomainResult = TrustDomain.of("DoMAin.TesT");

        assertEquals("domain.test", trustDomainResult.getValue().toString());
    }

    @Test
    void of_givenAStringWithTrailingAndLeadingBlanks_returnNormalizedTrustDomain() {
        val trustDomainResult = TrustDomain.of(" domain.test ");

        assertEquals("domain.test", trustDomainResult.getValue().toString());
    }

    @Test
    void of_nullString_ThrowsIllegalArgumentException() {
        val trustDomainResult = TrustDomain.of(null);

        assertAll(
                () -> assertEquals(Error.class, trustDomainResult.getClass()),
                () -> assertEquals("Trust Domain cannot be empty.", trustDomainResult.getError())
        );
    }

    @Test
    void of_emptyString_ThrowsIllegalArgumentException() {
        val trustDomainResult = TrustDomain.of("");
        assertAll(
                () -> assertEquals(Error.class, trustDomainResult.getClass()),
                () -> assertEquals("Trust Domain cannot be empty.", trustDomainResult.getError())
        );
    }

    @Test
    void of_blankString_ThrowsIllegalArgumentException() {
        val trustDomainResult = TrustDomain.of(" ");
        assertAll(
                () -> assertEquals(Error.class, trustDomainResult.getClass()),
                () -> assertEquals("Trust Domain cannot be empty.", trustDomainResult.getError())
        );
    }

    @Test
    void equals_twoTrustDomainObjectsWithTheSameString_returnsTrue() {
        val trustDomainResult1 = TrustDomain.of("example.org");
        val trustDomainResult2 = TrustDomain.of("example.org");

        assertEquals(trustDomainResult1.getValue(), trustDomainResult2.getValue());
    }

    @Test
    void equals_twoTrustDomainObjectsWithDifferentStrings_returnsFalse() {
        val trustDomainResult1 = TrustDomain.of("example.org");
        val trustDomainResult2 = TrustDomain.of("other.org");

        assertNotEquals(trustDomainResult1.getValue(), trustDomainResult2.getValue());
    }
}
