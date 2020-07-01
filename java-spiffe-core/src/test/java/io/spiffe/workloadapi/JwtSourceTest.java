package io.spiffe.workloadapi;

import com.google.common.collect.Sets;
import io.spiffe.bundle.jwtbundle.JwtBundle;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.exception.JwtSourceException;
import io.spiffe.exception.JwtSvidException;
import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.svid.jwtsvid.JwtSvid;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class JwtSourceTest {

    private JwtSource jwtSource;
    private WorkloadApiClientStub workloadApiClient;

    @BeforeEach
    void setUp() throws JwtSourceException, SocketEndpointAddressException {
        workloadApiClient = new WorkloadApiClientStub();
        JwtSource.JwtSourceOptions options = JwtSource.JwtSourceOptions.builder().workloadApiClient(workloadApiClient).build();
        jwtSource = JwtSource.newSource(options);
    }

    @AfterEach
    void tearDown() {
        jwtSource.close();
    }

    @Test
    void testgetBundleForTrustDomain() {
        try {
            JwtBundle bundle = jwtSource.getBundleForTrustDomain(TrustDomain.of("example.org"));
            assertNotNull(bundle);
            assertEquals(TrustDomain.of("example.org"), bundle.getTrustDomain());
        } catch (BundleNotFoundException e) {
            fail(e);
        }
    }

    @Test
    void testGetBundleForTrustDomain_SourceIsClosed_ThrowsIllegalStateException() {
        jwtSource.close();
        try {
            jwtSource.getBundleForTrustDomain(TrustDomain.of("example.org"));
            fail("expected exception");
        } catch (IllegalStateException e) {
            assertEquals("JWT bundle source is closed", e.getMessage());
            assertTrue(workloadApiClient.closed);
        } catch (BundleNotFoundException e) {
            fail("not expected exception", e);
        }
    }

    @Test
    void testFetchJwtSvid() {
        try {
            JwtSvid svid = jwtSource.fetchJwtSvid(SpiffeId.parse("spiffe://example.org/workload-server"), "aud1", "aud2", "aud3");
            assertNotNull(svid);
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svid.getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svid.getAudience());
        } catch (JwtSvidException e) {
            fail(e);
        }
    }

    @Test
    void testFetchJwtSvid_SourceIsClosed_ThrowsIllegalStateException() {
        jwtSource.close();
        try {
            jwtSource.fetchJwtSvid(SpiffeId.parse("spiffe://example.org/workload-server"), "aud1", "aud2", "aud3");
            fail("expected exception");
        } catch (IllegalStateException e) {
            assertEquals("JWT SVID source is closed", e.getMessage());
            assertTrue(workloadApiClient.closed);
        } catch (JwtSvidException e) {
            fail(e);
        }
    }
}