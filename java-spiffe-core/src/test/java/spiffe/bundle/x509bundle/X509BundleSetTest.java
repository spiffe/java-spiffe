package spiffe.bundle.x509bundle;

import org.junit.jupiter.api.Test;
import spiffe.exception.BundleNotFoundException;
import spiffe.internal.DummyX509Certificate;
import spiffe.spiffeid.TrustDomain;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class X509BundleSetTest {

    @Test
    void testOf_listOfBundles_Success() {
        X509Bundle x509Bundle1 = new X509Bundle(TrustDomain.of("example.org"));
        X509Bundle x509Bundle2 = new X509Bundle(TrustDomain.of("other.org"));
        List<X509Bundle> bundleList = Arrays.asList(x509Bundle1, x509Bundle2);
        X509BundleSet bundleSet = X509BundleSet.of(bundleList);

        assertTrue(bundleSet.getBundles().containsValue(x509Bundle1));
        assertTrue(bundleSet.getBundles().containsValue(x509Bundle2));
    }

    @Test
    void testOf_null_throwsNullPointerException() {
        try {
            X509BundleSet.of(null);
            fail("should have thrown exception");
        } catch (NullPointerException e) {
            assertEquals("bundles is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testAdd() {
        X509Bundle x509Bundle1 = new X509Bundle(TrustDomain.of("example.org"));
        List<X509Bundle> bundleList = Collections.singletonList(x509Bundle1);
        X509BundleSet bundleSet = X509BundleSet.of(bundleList);

        X509Bundle x509Bundle2 = new X509Bundle(TrustDomain.of("other.org"));
        bundleSet.put(x509Bundle2);

        assertTrue(bundleSet.getBundles().containsValue(x509Bundle1));
        assertTrue(bundleSet.getBundles().containsValue(x509Bundle2));
    }

    @Test
    void testAdd_sameBundleAgain_noDuplicate() {
        X509Bundle x509Bundle1 = new X509Bundle(TrustDomain.of("example.org"));
        List<X509Bundle> bundleList = Collections.singletonList(x509Bundle1);
        X509BundleSet bundleSet = X509BundleSet.of(bundleList);

        bundleSet.put(x509Bundle1);

        assertTrue(bundleSet.getBundles().containsValue(x509Bundle1));
        assertEquals(1, bundleSet.getBundles().size());
    }

    @Test
    void testAdd_aDifferentBundleForSameTrustDomain_replacesWithNewBundle() {
        X509Bundle x509Bundle1 = new X509Bundle(TrustDomain.of("example.org"));
        List<X509Bundle> bundleList = Collections.singletonList(x509Bundle1);
        X509BundleSet bundleSet = X509BundleSet.of(bundleList);

        X509Bundle x509Bundle2 = new X509Bundle(TrustDomain.of("example.org"));
        x509Bundle2.addX509Authority(new DummyX509Certificate());
        bundleSet.put(x509Bundle2);

        assertTrue(bundleSet.getBundles().containsValue(x509Bundle2));
        assertFalse(bundleSet.getBundles().containsValue(x509Bundle1));
        assertEquals(1, bundleSet.getBundles().size());
    }

    @Test
    void testAdd_nullBundle_throwsNullPointerException() {
        X509Bundle x509Bundle1 = new X509Bundle(TrustDomain.of("example.org"));
        List<X509Bundle> bundleList = Collections.singletonList(x509Bundle1);
        X509BundleSet bundleSet = X509BundleSet.of(bundleList);

        try {
            bundleSet.put(null);
            fail("should have thrown exception");
        } catch (NullPointerException e) {
            assertEquals("x509Bundle is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testgetBundleForTrustDomain_Success() throws BundleNotFoundException {
        X509Bundle x509Bundle1 = new X509Bundle(TrustDomain.of("example.org"));
        X509Bundle x509Bundle2 = new X509Bundle(TrustDomain.of("other.org"));
        List<X509Bundle> bundleList = Arrays.asList(x509Bundle1, x509Bundle2);
        X509BundleSet bundleSet = X509BundleSet.of(bundleList);

        assertEquals(x509Bundle1, bundleSet.getBundleForTrustDomain(TrustDomain.of("example.org")));
        assertEquals(x509Bundle2, bundleSet.getBundleForTrustDomain(TrustDomain.of("other.org")));
    }

    @Test
    void testgetBundleForTrustDomain_notFoundTrustDomain() {
        X509Bundle x509Bundle1 = new X509Bundle(TrustDomain.of("example.org"));
        X509Bundle x509Bundle2 = new X509Bundle(TrustDomain.of("other.org"));
        List<X509Bundle> bundleList = Arrays.asList(x509Bundle1, x509Bundle2);
        X509BundleSet bundleSet = X509BundleSet.of(bundleList);

        try {
            bundleSet.getBundleForTrustDomain(TrustDomain.of("unknown.org"));
            fail("expected BundleNotFoundException");
        } catch (BundleNotFoundException e) {
            assertEquals("No X509 bundle for trust domain unknown.org", e.getMessage());
        }
    }

    @Test
    void testgetBundleForTrustDomain_nullTrustDomain_throwsException() throws BundleNotFoundException {
        X509Bundle x509Bundle1 = new X509Bundle(TrustDomain.of("example.org"));
        X509Bundle x509Bundle2 = new X509Bundle(TrustDomain.of("other.org"));
        List<X509Bundle> bundleList = Arrays.asList(x509Bundle1, x509Bundle2);
        X509BundleSet bundleSet = X509BundleSet.of(bundleList);

        try {
            bundleSet.getBundleForTrustDomain(null);
            fail("expected exception");
        } catch (NullPointerException e) {
            assertEquals("trustDomain is marked non-null but is null", e.getMessage());
        }
    }
}