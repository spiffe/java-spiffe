package spiffe.bundle.jwtbundle;

import org.junit.jupiter.api.Test;
import spiffe.exception.BundleNotFoundException;
import spiffe.internal.DummyPublicKey;
import spiffe.spiffeid.TrustDomain;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JwtBundleSetTest {

    @Test
    void testOfListOfBundles() {
        JwtBundle jwtBundle1 = new JwtBundle(TrustDomain.of("example.org"));
        JwtBundle jwtBundle2 = new JwtBundle(TrustDomain.of("other.org"));

        List<JwtBundle> bundles = Arrays.asList(jwtBundle1, jwtBundle2);

        JwtBundleSet bundleSet = JwtBundleSet.of(bundles);

        assertNotNull(bundleSet);
        assertEquals(2, bundleSet.getBundles().size());
        assertEquals(jwtBundle1, bundleSet.getBundles().get(TrustDomain.of("example.org")));
        assertEquals(jwtBundle2, bundleSet.getBundles().get(TrustDomain.of("other.org")));
    }

    @Test
    void getBundleForTrustDomain_Success() {
        JwtBundle jwtBundle1 = new JwtBundle(TrustDomain.of("example.org"));
        JwtBundle jwtBundle2 = new JwtBundle(TrustDomain.of("other.org"));
        List<JwtBundle> bundles = Arrays.asList(jwtBundle1, jwtBundle2);
        JwtBundleSet bundleSet = JwtBundleSet.of(bundles);

        JwtBundle bundle = null;
        try {
            bundle = bundleSet.getBundleForTrustDomain(TrustDomain.of("example.org"));
        } catch (BundleNotFoundException e) {
            fail(e);
        }

        assertEquals(jwtBundle1, bundle);
    }

    @Test
    void testOf_null_throwsNullPointerException() {
        try {
            JwtBundleSet.of(null);
            fail("should have thrown exception");
        } catch (NullPointerException e) {
            assertEquals("bundles is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testgetBundleForTrustDomain_TrustDomainNotInSet_ThrowsBundleNotFoundException() {
        JwtBundle jwtBundle1 = new JwtBundle(TrustDomain.of("example.org"));
        JwtBundle jwtBundle2 = new JwtBundle(TrustDomain.of("other.org"));
        List<JwtBundle> bundles = Arrays.asList(jwtBundle1, jwtBundle2);
        JwtBundleSet bundleSet = JwtBundleSet.of(bundles);

        try {
            bundleSet.getBundleForTrustDomain(TrustDomain.of("domain.test"));
            fail("exception expected");
        } catch (BundleNotFoundException e) {
            assertEquals("No JWT bundle for trust domain domain.test", e.getMessage());
        }
    }

    @Test
    void testgetBundleForTrustDomain_null_throwsNullPointerException() throws BundleNotFoundException {
        JwtBundle jwtBundle1 = new JwtBundle(TrustDomain.of("example.org"));
        List<JwtBundle> bundleList = Collections.singletonList(jwtBundle1);
        JwtBundleSet bundleSet = JwtBundleSet.of(bundleList);
        try {
            bundleSet.getBundleForTrustDomain(null);
        } catch (NullPointerException e) {
            assertEquals("trustDomain is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testAdd() {
        JwtBundle jwtBundle1 = new JwtBundle(TrustDomain.of("example.org"));
        List<JwtBundle> bundleList = Collections.singletonList(jwtBundle1);
        JwtBundleSet bundleSet = JwtBundleSet.of(bundleList);

        JwtBundle jwtBundle2 = new JwtBundle(TrustDomain.of("other.org"));
        bundleSet.add(jwtBundle2);

        assertTrue(bundleSet.getBundles().containsValue(jwtBundle1));
        assertTrue(bundleSet.getBundles().containsValue(jwtBundle2));
    }

    @Test
    void testAdd_sameBundleAgain_noDuplicate() {
        JwtBundle jwtBundle1 = new JwtBundle(TrustDomain.of("example.org"));
        List<JwtBundle> bundleList = Collections.singletonList(jwtBundle1);
        JwtBundleSet bundleSet = JwtBundleSet.of(bundleList);

        bundleSet.add(jwtBundle1);

        assertEquals(1, bundleSet.getBundles().size());
        assertTrue(bundleSet.getBundles().containsValue(jwtBundle1));
    }

    @Test
    void testAdd_aDifferentBundleForSameTrustDomain_replacesWithNewBundle() {
        JwtBundle jwtBundle1 = new JwtBundle(TrustDomain.of("example.org"));
        List<JwtBundle> bundleList = Collections.singletonList(jwtBundle1);
        JwtBundleSet bundleSet = JwtBundleSet.of(bundleList);

        JwtBundle jwtBundle2 = new JwtBundle(TrustDomain.of("example.org"));
        jwtBundle2.putJwtAuthority("key1", new DummyPublicKey());
        bundleSet.add(jwtBundle2);

        assertTrue(bundleSet.getBundles().containsValue(jwtBundle2));
        assertFalse(bundleSet.getBundles().containsValue(jwtBundle1));
    }

    @Test
    void add_null_throwsNullPointerException() {
        JwtBundle jwtBundle1 = new JwtBundle(TrustDomain.of("example.org"));
        List<JwtBundle> bundleList = Collections.singletonList(jwtBundle1);
        JwtBundleSet bundleSet = JwtBundleSet.of(bundleList);
        try {
            bundleSet.add(null);
        } catch (NullPointerException e) {
            assertEquals("jwtBundle is marked non-null but is null", e.getMessage());
        }
    }
}