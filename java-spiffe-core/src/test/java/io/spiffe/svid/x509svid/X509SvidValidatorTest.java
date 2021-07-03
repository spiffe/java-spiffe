package io.spiffe.svid.x509svid;

import com.google.common.collect.Sets;
import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.utils.CertAndKeyPair;
import lombok.val;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

import static io.spiffe.utils.X509CertificateTestUtils.createCertificate;
import static io.spiffe.utils.X509CertificateTestUtils.createRootCA;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class X509SvidValidatorTest {

    List<X509Certificate> chain;
    CertAndKeyPair rootCa;
    CertAndKeyPair otherRootCa;
    CertAndKeyPair leaf;

    @BeforeEach
    void setUp() throws Exception {
        rootCa = createRootCA("C = US, O = SPIFFE", "spiffe://example.org" );
        val intermediate1 = createCertificate("C = US, O = SPIRE", "C = US, O = SPIFFE",  "spiffe://example.org/host", rootCa, true);
        val intermediate2 = createCertificate("C = US, O = SPIRE", "C = US, O = SPIRE",  "spiffe://example.org/host2", intermediate1, true);
        leaf = createCertificate("C = US, O = SPIRE", "C = US, O = SPIRE",  "spiffe://example.org/test", intermediate2, false);
        chain = Arrays.asList(leaf.getCertificate(), intermediate2.getCertificate(), intermediate1.getCertificate());
        otherRootCa = createRootCA("C = US, O = SPIFFE", "spiffe://example.org" );
    }

    @Test
    void testVerifyChain_chainCanBeVerifiedWithAuthorityInBundle() throws Exception {
        HashSet<X509Certificate> x509Authorities = new HashSet<>();
        x509Authorities.add(rootCa.getCertificate());
        x509Authorities.add(otherRootCa.getCertificate());

        val x509Bundle = new X509Bundle(TrustDomain.parse("example.org"), x509Authorities);
        X509SvidValidator.verifyChain(chain, x509Bundle);
    }

    @Test
    void testVerifyChain_chainCannotBeVerifiedWithAuthorityInBundle_throwsCertificateException() throws Exception {
        HashSet<X509Certificate> x509Authorities = new HashSet<>();
        x509Authorities.add(otherRootCa.getCertificate());

        val x509Bundle = new X509Bundle(TrustDomain.parse("example.org"), x509Authorities);
        try {
            X509SvidValidator.verifyChain(chain, x509Bundle);
            fail("exception is expected");
        } catch (CertificateException e) {
            assertEquals("Cert chain cannot be verified", e.getMessage());
        }
    }

    @Test
    void verifyChain_noBundleForTrustDomain_throwsBundleNotFoundException() throws Exception {
        HashSet<X509Certificate> x509Authorities = new HashSet<>();
        x509Authorities.add(otherRootCa.getCertificate());

        val x509Bundle = new X509Bundle(TrustDomain.parse("other.org"), x509Authorities);

        try {
            X509SvidValidator.verifyChain(chain, x509Bundle);
            fail("Verify chain should have thrown validation exception");
        } catch (BundleNotFoundException e) {
            assertEquals("No X.509 bundle found for trust domain example.org", e.getMessage());
        }
    }

    @Test
    void verifySpiffeId_givenASpiffeIdInTheListOfAcceptedIds_doesntThrowException() throws IOException, CertificateException, URISyntaxException {
        val spiffeId1 = SpiffeId.parse("spiffe://example.org/test");
        val spiffeId2 = SpiffeId.parse("spiffe://example.org/test2");

        val spiffeIdSet = Sets.newHashSet(spiffeId1, spiffeId2);

        X509SvidValidator.verifySpiffeId(leaf.getCertificate(), () -> spiffeIdSet);
    }

    @Test
    void verifySpiffeId_givenASpiffeIdNotInTheListOfAcceptedIds_throwsCertificateException() throws IOException, CertificateException, URISyntaxException {
        val spiffeId1 = SpiffeId.parse("spiffe://example.org/other1");
        val spiffeId2 = SpiffeId.parse("spiffe://example.org/other2");
        val spiffeIdSet = Sets.newHashSet(spiffeId1, spiffeId2);

        try {
            X509SvidValidator.verifySpiffeId(leaf.getCertificate(), () -> spiffeIdSet);
            fail("Should have thrown CertificateException");
        } catch (CertificateException e) {
            assertEquals("SPIFFE ID spiffe://example.org/test in X.509 certificate is not accepted", e.getMessage());
        }
    }

    @Test
    void verifySpiffeId_givenAnEmptySupplier_throwsCertificateException() {
        try {
            X509SvidValidator.verifySpiffeId(leaf.getCertificate(), Collections::emptySet);
            fail("Should have thrown CertificateException");
        } catch (CertificateException e) {
            assertEquals("The supplier of accepted SPIFFE IDs supplied an empty set", e.getMessage());
        }

    }

    @Test
    void checkSpiffeId_nullX509Certificate_throwsNullPointerException() throws CertificateException {
        try {
            X509SvidValidator.verifySpiffeId(null, Collections::emptySet);
            fail("should have thrown an exception");
        } catch (NullPointerException e) {
            assertEquals("x509Certificate is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void checkSpiffeId_nullAcceptedSpiffeIdsSuppplier_throwsNullPointerException() throws CertificateException, URISyntaxException, IOException {
        try {
            X509SvidValidator.verifySpiffeId(leaf.getCertificate(), null);
            fail("should have thrown an exception");
        } catch (NullPointerException e) {
            assertEquals("acceptedSpiffeIdsSupplier is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void verifyChain_nullChain_throwsNullPointerException() throws CertificateException, BundleNotFoundException {
        try {
            X509SvidValidator.verifyChain(null, new X509Bundle(TrustDomain.parse("example.org")));
            fail("should have thrown an exception");
        } catch (NullPointerException e) {
            assertEquals("chain is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void verifyChain_nullBundleSource_throwsNullPointerException() throws CertificateException, BundleNotFoundException, URISyntaxException, IOException {
        try {
            X509SvidValidator.verifyChain(chain, null);
            fail("should have thrown an exception");
        } catch (NullPointerException e) {
            assertEquals("x509BundleSource is marked non-null but is null", e.getMessage());
        }
    }
}
