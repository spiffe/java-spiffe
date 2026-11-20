package io.spiffe.provider;

import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SpiffeIdVerifierTest {

    private static final X509Certificate[] CHAIN = new X509Certificate[0];

    private static final TrustDomain TRUST_DOMAIN = TrustDomain.parse("example.org");
    private static final SpiffeId SPIFFE_ID_1 = SpiffeId.parse("spiffe://example.org/workload1");
    private static final SpiffeId SPIFFE_ID_2 = SpiffeId.parse("spiffe://example.org/workload2");
    private static final SpiffeId SPIFFE_ID_3 = SpiffeId.parse("spiffe://example.org/workload3");
    private static final SpiffeId OTHER_DOMAIN_SPIFFE_ID = SpiffeId.parse("spiffe://other.org/workload1");

    @Test
    void acceptAny_acceptsAnySpiffeId() {
        SpiffeIdVerifier verifier = SpiffeIdVerifier.acceptAny();

        assertDoesNotThrow(() -> verifier.verify(SPIFFE_ID_1, CHAIN));
        assertDoesNotThrow(() -> verifier.verify(OTHER_DOMAIN_SPIFFE_ID, CHAIN));
        assertDoesNotThrow(() -> verifier.verify(TRUST_DOMAIN.newSpiffeId(), CHAIN));
    }

    @Test
    void acceptId_acceptsTheGivenSpiffeId() {
        SpiffeIdVerifier verifier = SpiffeIdVerifier.acceptId(SPIFFE_ID_1);

        assertDoesNotThrow(() -> verifier.verify(SpiffeId.parse("spiffe://example.org/workload1"), CHAIN));
    }

    @Test
    void acceptId_rejectsOtherSpiffeIds() {
        SpiffeIdVerifier verifier = SpiffeIdVerifier.acceptId(SPIFFE_ID_1);

        SpiffeVerificationException e = assertThrows(SpiffeVerificationException.class,
                () -> verifier.verify(SPIFFE_ID_2, CHAIN));
        assertEquals("SPIFFE ID spiffe://example.org/workload2 in X.509 certificate is not accepted", e.getMessage());
        assertThrows(SpiffeVerificationException.class, () -> verifier.verify(OTHER_DOMAIN_SPIFFE_ID, CHAIN));
        assertThrows(SpiffeVerificationException.class,
                () -> verifier.verify(SpiffeId.parse("spiffe://example.org/workload1/child"), CHAIN));
    }

    @Test
    void acceptId_nullSpiffeId() {
        NullPointerException e = assertThrows(NullPointerException.class, () -> SpiffeIdVerifier.acceptId(null));
        assertEquals("allowedSpiffeId must not be null", e.getMessage());
    }

    @Test
    void acceptOneOf_array_acceptsTheGivenSpiffeIds() {
        SpiffeIdVerifier verifier = SpiffeIdVerifier.acceptOneOf(SPIFFE_ID_1, SPIFFE_ID_2);

        assertDoesNotThrow(() -> verifier.verify(SPIFFE_ID_1, CHAIN));
        assertDoesNotThrow(() -> verifier.verify(SPIFFE_ID_2, CHAIN));
        SpiffeVerificationException e = assertThrows(SpiffeVerificationException.class,
                () -> verifier.verify(SPIFFE_ID_3, CHAIN));
        assertEquals("SPIFFE ID spiffe://example.org/workload3 in X.509 certificate is not accepted", e.getMessage());
    }

    @Test
    void acceptOneOf_collection_acceptsTheGivenSpiffeIds() {
        SpiffeIdVerifier verifier = SpiffeIdVerifier.acceptOneOf(Arrays.asList(SPIFFE_ID_1, SPIFFE_ID_2));

        assertDoesNotThrow(() -> verifier.verify(SPIFFE_ID_1, CHAIN));
        assertDoesNotThrow(() -> verifier.verify(SPIFFE_ID_2, CHAIN));
        SpiffeVerificationException e = assertThrows(SpiffeVerificationException.class,
                () -> verifier.verify(SPIFFE_ID_3, CHAIN));
        assertEquals("SPIFFE ID spiffe://example.org/workload3 in X.509 certificate is not accepted", e.getMessage());
    }

    @Test
    void acceptOneOf_array_copiesTheSpiffeIds() {
        SpiffeId[] allowedSpiffeIds = {SPIFFE_ID_1};
        SpiffeIdVerifier verifier = SpiffeIdVerifier.acceptOneOf(allowedSpiffeIds);

        allowedSpiffeIds[0] = SPIFFE_ID_2;

        assertDoesNotThrow(() -> verifier.verify(SPIFFE_ID_1, CHAIN));
        assertThrows(SpiffeVerificationException.class, () -> verifier.verify(SPIFFE_ID_2, CHAIN));
    }

    @Test
    void acceptOneOf_collection_copiesTheSpiffeIds() {
        List<SpiffeId> allowedSpiffeIds = new ArrayList<>(Collections.singletonList(SPIFFE_ID_1));
        SpiffeIdVerifier verifier = SpiffeIdVerifier.acceptOneOf(allowedSpiffeIds);

        allowedSpiffeIds.add(SPIFFE_ID_2);
        allowedSpiffeIds.remove(SPIFFE_ID_1);

        assertDoesNotThrow(() -> verifier.verify(SPIFFE_ID_1, CHAIN));
        assertThrows(SpiffeVerificationException.class, () -> verifier.verify(SPIFFE_ID_2, CHAIN));
    }

    @Test
    void acceptOneOf_noSpiffeIds_rejectsEverySpiffeId() {
        SpiffeIdVerifier arrayVerifier = SpiffeIdVerifier.acceptOneOf();
        SpiffeIdVerifier collectionVerifier = SpiffeIdVerifier.acceptOneOf(Collections.emptySet());

        assertThrows(SpiffeVerificationException.class, () -> arrayVerifier.verify(SPIFFE_ID_1, CHAIN));
        assertThrows(SpiffeVerificationException.class, () -> collectionVerifier.verify(SPIFFE_ID_1, CHAIN));
    }

    @Test
    void acceptOneOf_nullArguments() {
        NullPointerException e = assertThrows(NullPointerException.class,
                () -> SpiffeIdVerifier.acceptOneOf((SpiffeId[]) null));
        assertEquals("allowedSpiffeIds must not be null", e.getMessage());

        e = assertThrows(NullPointerException.class,
                () -> SpiffeIdVerifier.acceptOneOf((List<SpiffeId>) null));
        assertEquals("allowedSpiffeIds must not be null", e.getMessage());
    }

    @Test
    void acceptOneOf_nullElement() {
        NullPointerException e = assertThrows(NullPointerException.class,
                () -> SpiffeIdVerifier.acceptOneOf(SPIFFE_ID_1, null));
        assertEquals("allowedSpiffeIds must not contain null elements", e.getMessage());

        e = assertThrows(NullPointerException.class,
                () -> SpiffeIdVerifier.acceptOneOf(Arrays.asList(SPIFFE_ID_1, null)));
        assertEquals("allowedSpiffeIds must not contain null elements", e.getMessage());
    }

    @Test
    void acceptMemberOf_acceptsSpiffeIdsInTheTrustDomain() {
        SpiffeIdVerifier verifier = SpiffeIdVerifier.acceptMemberOf(TRUST_DOMAIN);

        assertDoesNotThrow(() -> verifier.verify(SPIFFE_ID_1, CHAIN));
        assertDoesNotThrow(() -> verifier.verify(SPIFFE_ID_2, CHAIN));
        assertDoesNotThrow(() -> verifier.verify(SpiffeId.parse("spiffe://EXAMPLE.org/workload1/child"), CHAIN));
    }

    @Test
    void acceptMemberOf_rejectsSpiffeIdsInOtherTrustDomains() {
        SpiffeIdVerifier verifier = SpiffeIdVerifier.acceptMemberOf(TRUST_DOMAIN);

        SpiffeVerificationException e = assertThrows(SpiffeVerificationException.class,
                () -> verifier.verify(OTHER_DOMAIN_SPIFFE_ID, CHAIN));
        assertEquals("SPIFFE ID spiffe://other.org/workload1 in X.509 certificate is not a member of trust domain example.org",
                e.getMessage());
        assertThrows(SpiffeVerificationException.class,
                () -> verifier.verify(SpiffeId.parse("spiffe://example.org.other/workload1"), CHAIN));
    }

    @Test
    void verifiers_rejectNullSpiffeId() {
        assertThrows(SpiffeVerificationException.class,
                () -> SpiffeIdVerifier.acceptId(SPIFFE_ID_1).verify(null, CHAIN));
        assertThrows(SpiffeVerificationException.class,
                () -> SpiffeIdVerifier.acceptOneOf(SPIFFE_ID_1).verify(null, CHAIN));
        assertThrows(SpiffeVerificationException.class,
                () -> SpiffeIdVerifier.acceptMemberOf(TRUST_DOMAIN).verify(null, CHAIN));
    }

    @Test
    void acceptMemberOf_nullTrustDomain() {
        NullPointerException e = assertThrows(NullPointerException.class, () -> SpiffeIdVerifier.acceptMemberOf(null));
        assertEquals("trustDomain must not be null", e.getMessage());
    }
}
