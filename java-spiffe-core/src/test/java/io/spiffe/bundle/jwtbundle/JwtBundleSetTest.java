package io.spiffe.bundle.jwtbundle;

import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.internal.DummyPublicKey;
import io.spiffe.spiffeid.TrustDomain;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class JwtBundleSetTest {

    @Test
    void testOfListOfBundles() {
        JwtBundle jwtBundle1 = new JwtBundle(TrustDomain.parse("example.org"));
        JwtBundle jwtBundle2 = new JwtBundle(TrustDomain.parse("other.org"));

        List<JwtBundle> bundles = Arrays.asList(jwtBundle1, jwtBundle2);

        JwtBundleSet bundleSet = JwtBundleSet.of(bundles);

        assertNotNull(bundleSet);
        assertEquals(2, bundleSet.getBundles().size());
        assertEquals(jwtBundle1, bundleSet.getBundles().get(TrustDomain.parse("example.org")));
        assertEquals(jwtBundle2, bundleSet.getBundles().get(TrustDomain.parse("other.org")));
    }

    @Test
    void getBundleForTrustDomain_Success() {
        JwtBundle jwtBundle1 = new JwtBundle(TrustDomain.parse("example.org"));
        JwtBundle jwtBundle2 = new JwtBundle(TrustDomain.parse("other.org"));
        List<JwtBundle> bundles = Arrays.asList(jwtBundle1, jwtBundle2);
        JwtBundleSet bundleSet = JwtBundleSet.of(bundles);

        JwtBundle bundle = null;
        try {
            bundle = bundleSet.getBundleForTrustDomain(TrustDomain.parse("example.org"));
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
    void testOf_EmptyCollection_throwsIllegalArgumentException() {
        try {
            JwtBundleSet.of(Collections.emptySet());
            fail("should have thrown exception");
        } catch (IllegalArgumentException e) {
            assertEquals("JwtBundle collection is empty", e.getMessage());
        }
    }

    @Test
    void testEmptySet() {
        JwtBundleSet jwtBundleSet = JwtBundleSet.emptySet();
        assertNotNull(jwtBundleSet);
        assertEquals(0, jwtBundleSet.getBundles().size());
    }

    @Test
    void testgetBundleForTrustDomain_TrustDomainNotInSet_ThrowsBundleNotFoundException() {
        JwtBundle jwtBundle1 = new JwtBundle(TrustDomain.parse("example.org"));
        JwtBundle jwtBundle2 = new JwtBundle(TrustDomain.parse("other.org"));
        List<JwtBundle> bundles = Arrays.asList(jwtBundle1, jwtBundle2);
        JwtBundleSet bundleSet = JwtBundleSet.of(bundles);

        try {
            bundleSet.getBundleForTrustDomain(TrustDomain.parse("domain.test"));
            fail("exception expected");
        } catch (BundleNotFoundException e) {
            assertEquals("No JWT bundle for trust domain domain.test", e.getMessage());
        }
    }

    @Test
    void testgetBundleForTrustDomain_null_throwsNullPointerException() throws BundleNotFoundException {
        JwtBundle jwtBundle1 = new JwtBundle(TrustDomain.parse("example.org"));
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
        JwtBundle jwtBundle1 = new JwtBundle(TrustDomain.parse("example.org"));
        List<JwtBundle> bundleList = Collections.singletonList(jwtBundle1);
        JwtBundleSet bundleSet = JwtBundleSet.of(bundleList);

        JwtBundle jwtBundle2 = new JwtBundle(TrustDomain.parse("other.org"));
        bundleSet.put(jwtBundle2);

        assertTrue(bundleSet.getBundles().containsValue(jwtBundle1));
        assertTrue(bundleSet.getBundles().containsValue(jwtBundle2));
    }

    @Test
    void testAdd_sameBundleAgain_noDuplicate() {
        JwtBundle jwtBundle1 = new JwtBundle(TrustDomain.parse("example.org"));
        List<JwtBundle> bundleList = Collections.singletonList(jwtBundle1);
        JwtBundleSet bundleSet = JwtBundleSet.of(bundleList);

        bundleSet.put(jwtBundle1);

        assertEquals(1, bundleSet.getBundles().size());
        assertTrue(bundleSet.getBundles().containsValue(jwtBundle1));
    }

    @Test
    void testAdd_aDifferentBundleForSameTrustDomain_replacesWithNewBundle() {
        JwtBundle jwtBundle1 = new JwtBundle(TrustDomain.parse("example.org"));
        List<JwtBundle> bundleList = Collections.singletonList(jwtBundle1);
        JwtBundleSet bundleSet = JwtBundleSet.of(bundleList);

        JwtBundle jwtBundle2 = new JwtBundle(TrustDomain.parse("example.org"));
        jwtBundle2.putJwtAuthority("key1", new DummyPublicKey());
        bundleSet.put(jwtBundle2);

        assertTrue(bundleSet.getBundles().containsValue(jwtBundle2));
        assertFalse(bundleSet.getBundles().containsValue(jwtBundle1));
    }

    @Test
    void add_null_throwsNullPointerException() {
        JwtBundle jwtBundle1 = new JwtBundle(TrustDomain.parse("example.org"));
        List<JwtBundle> bundleList = Collections.singletonList(jwtBundle1);
        JwtBundleSet bundleSet = JwtBundleSet.of(bundleList);
        try {
            bundleSet.put(null);
        } catch (NullPointerException e) {
            assertEquals("jwtBundle is marked non-null but is null", e.getMessage());
        }
    }
}