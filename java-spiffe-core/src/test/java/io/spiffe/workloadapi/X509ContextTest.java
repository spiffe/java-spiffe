package io.spiffe.workloadapi;

import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.bundle.x509bundle.X509BundleSet;
import io.spiffe.spiffeid.TrustDomain;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

class X509ContextTest {

    @Test
    void of_NullListOfX509SvidsParameter() {
        try {
            X509Context.of(null, createBundleSet());
            fail();
        } catch (NullPointerException e) {
            assertEquals("x509Svids is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void of_EmtpyListOfX509SvidsParameter() {
        try {
            X509Context.of(Collections.emptyList(), createBundleSet());
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("The X.509 Context must have a least one X.509 SVID", e.getMessage());
        }
    }

    @Test
    void getNewllX509BundleSet() {
        try {
            X509Context.of(Collections.emptyList(), null);
            fail();
        } catch (NullPointerException e) {
            assertEquals("x509BundleSet is marked non-null but is null", e.getMessage());
        }
    }
    
    private X509BundleSet createBundleSet() {
        X509Bundle x509Bundle1 = new X509Bundle(TrustDomain.parse("example.org"));
        X509Bundle x509Bundle2 = new X509Bundle(TrustDomain.parse("other.org"));
        List<X509Bundle> bundleList = Arrays.asList(x509Bundle1, x509Bundle2);
        return X509BundleSet.of(bundleList);
    }

}