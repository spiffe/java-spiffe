package io.spiffe.provider;

import io.spiffe.bundle.BundleSource;
import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.workloadapi.X509Source;
import org.junit.jupiter.api.Test;

import javax.net.ssl.TrustManager;
import java.lang.reflect.Field;
import java.util.Set;
import java.util.function.Supplier;

import static io.spiffe.provider.SpiffeProviderConstants.SSL_SPIFFE_ACCEPT_PROPERTY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SpiffeTrustManagerFactoryTest {

    @Test
    void engineGetTrustManagers() throws Exception {
        System.setProperty(SSL_SPIFFE_ACCEPT_PROPERTY, "spiffe://example.org/test1|spiffe://example.org/test2" );

        // init singleton with an instance
        Field field = X509SourceManager.class.getDeclaredField("x509Source");
        field.setAccessible(true);
        X509Source source = new X509SourceStub();
        field.set(null, source);

        TrustManager[] trustManagers = new SpiffeTrustManagerFactory().engineGetTrustManagers();
        SpiffeTrustManager trustManager = (SpiffeTrustManager) trustManagers[0];

        BundleSource<X509Bundle> bundleSource = getX509BundleBundleSource(trustManager);
        Supplier<Set<SpiffeId>> supplier = getSetSupplier(trustManager);
        boolean acceptAny = isAcceptAny(trustManager);

        TrustDomain trustDomain = TrustDomain.parse("example.org");
        assertEquals(source.getBundleForTrustDomain(trustDomain), bundleSource.getBundleForTrustDomain(trustDomain));
        assertEquals(2, supplier.get().size());
        assertTrue(supplier.get().contains(SpiffeId.parse("spiffe://example.org/test1")));
        assertFalse(acceptAny);
    }


    @Test
    void testEngineGetTrustManagers_withCustomSource() throws NoSuchFieldException, IllegalAccessException, BundleNotFoundException {
        System.setProperty(SSL_SPIFFE_ACCEPT_PROPERTY, "spiffe://example.org/test1|spiffe://example.org/test2" );

        X509Source source = new X509SourceStub();
        TrustManager[] trustManagers = new SpiffeTrustManagerFactory().engineGetTrustManagers(source);
        SpiffeTrustManager trustManager = (SpiffeTrustManager) trustManagers[0];

        BundleSource<X509Bundle> bundleSource = getX509BundleBundleSource(trustManager);
        Supplier<Set<SpiffeId>> supplier = getSetSupplier(trustManager);
        boolean acceptAny = isAcceptAny(trustManager);

        TrustDomain trustDomain = TrustDomain.parse("example.org");
        assertEquals(source.getBundleForTrustDomain(trustDomain), bundleSource.getBundleForTrustDomain(trustDomain));
        assertEquals(2, supplier.get().size());
        assertTrue(supplier.get().contains(SpiffeId.parse("spiffe://example.org/test1")));
        assertFalse(acceptAny);
    }

    @Test
    void engineGetTrustManagersAcceptAnySpiffeId() throws NoSuchFieldException, IllegalAccessException {
        X509Source source = new X509SourceStub();
        TrustManager[] trustManagers = new SpiffeTrustManagerFactory().engineGetTrustManagersAcceptAnySpiffeId(source);
        SpiffeTrustManager trustManager = (SpiffeTrustManager) trustManagers[0];
        boolean acceptAny = isAcceptAny(trustManager);
        assertTrue(acceptAny);
    }

    @Test
    void engineGetTrustManagersAcceptAnySpiffeId_nullParameter() {
        try {
            new SpiffeTrustManagerFactory().engineGetTrustManagersAcceptAnySpiffeId(null);
        } catch (NullPointerException e) {
            assertEquals("x509BundleSource is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void engineGetTrustManagers_nullParameter() {
        try {
            new SpiffeTrustManagerFactory().engineGetTrustManagers(null);
        } catch (NullPointerException e) {
            assertEquals("x509BundleSource is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void engineGetTrustManagers_nullParameters() {
        try {
            new SpiffeTrustManagerFactory().engineGetTrustManagers(null, null);
        } catch (NullPointerException e) {
            assertEquals("x509BundleSource is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void engineGetTrustManagers_nullSupplier() {
        X509Source source = new X509SourceStub();
        try {
            new SpiffeTrustManagerFactory().engineGetTrustManagers(source, null);
        } catch (NullPointerException e) {
            assertEquals("acceptedSpiffeIdsSupplier is marked non-null but is null", e.getMessage());
        }
    }

    private BundleSource<X509Bundle> getX509BundleBundleSource(SpiffeTrustManager trustManager) throws NoSuchFieldException, IllegalAccessException {
        Field bundleField = SpiffeTrustManager.class.getDeclaredField("x509BundleSource");
        bundleField.setAccessible(true);
        return (BundleSource<X509Bundle>) bundleField.get(trustManager);
    }

    private Supplier<Set<SpiffeId>> getSetSupplier(SpiffeTrustManager trustManager) throws NoSuchFieldException, IllegalAccessException {
        Field supplierField = SpiffeTrustManager.class.getDeclaredField("acceptedSpiffeIdsSupplier");
        supplierField.setAccessible(true);
        return (Supplier<Set<SpiffeId>>) supplierField.get(trustManager);
    }

    private boolean isAcceptAny(SpiffeTrustManager trustManager) throws NoSuchFieldException, IllegalAccessException {
        Field acceptAnyField = SpiffeTrustManager.class.getDeclaredField("acceptAnySpiffeId");
        acceptAnyField.setAccessible(true);
        return (boolean) acceptAnyField.get(trustManager);
    }
}