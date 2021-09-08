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
import io.spiffe.utils.TestUtils;
import lombok.val;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class JwtSourceTest {

    private JwtSource jwtSource;
    private WorkloadApiClientStub workloadApiClient;
    private WorkloadApiClientErrorStub workloadApiClientErrorStub;

    @BeforeEach
    void setUp() throws JwtSourceException, SocketEndpointAddressException {
        workloadApiClient = new WorkloadApiClientStub();
        DefaultJwtSource.JwtSourceOptions options = DefaultJwtSource.JwtSourceOptions.builder().workloadApiClient(workloadApiClient).build();
        System.setProperty(DefaultJwtSource.TIMEOUT_SYSTEM_PROPERTY, "PT1S");
        jwtSource = DefaultJwtSource.newSource(options);
        workloadApiClientErrorStub = new WorkloadApiClientErrorStub();
    }

    @AfterEach
    void tearDown() throws IOException {
        jwtSource.close();
    }

    @Test
    void testGetBundleForTrustDomain() {
        try {
            JwtBundle bundle = jwtSource.getBundleForTrustDomain(TrustDomain.parse("example.org"));
            assertNotNull(bundle);
            assertEquals(TrustDomain.parse("example.org"), bundle.getTrustDomain());
        } catch (BundleNotFoundException e) {
            fail(e);
        }
    }

    @Test
    void testGetBundleForTrustDomain_nullParam() {
        try {
            jwtSource.getBundleForTrustDomain(null);
            fail();
        } catch (NullPointerException e) {
            assertEquals("trustDomain is marked non-null but is null", e.getMessage());
        } catch (BundleNotFoundException e) {
            fail();
        }
    }

    @Test
    void testGetBundleForTrustDomain_SourceIsClosed_ThrowsIllegalStateException() throws IOException {
        jwtSource.close();
        try {
            jwtSource.getBundleForTrustDomain(TrustDomain.parse("example.org"));
            fail("expected exception");
        } catch (IllegalStateException e) {
            assertEquals("JWT bundle source is closed", e.getMessage());
            assertTrue(workloadApiClient.closed);
        } catch (BundleNotFoundException e) {
            fail("not expected exception", e);
        }
    }

    @Test
    void testFetchJwtSvidWithSubject() {
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
    void testFetchJwtSvidWithoutSubject() {
        try {
            JwtSvid svid = jwtSource.fetchJwtSvid("aud1", "aud2", "aud3");
            assertNotNull(svid);
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svid.getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svid.getAudience());
        } catch (JwtSvidException e) {
            fail(e);
        }
    }

    @Test
    void testFetchJwtSvid_SourceIsClosed_ThrowsIllegalStateException() throws IOException {
        jwtSource.close();
        try {
            jwtSource.fetchJwtSvid("aud1", "aud2", "aud3");
            fail("expected exception");
        } catch (IllegalStateException e) {
            assertEquals("JWT SVID source is closed", e.getMessage());
            assertTrue(workloadApiClient.closed);
        } catch (JwtSvidException e) {
            fail(e);
        }
    }

    @Test
    void testFetchJwtSvidWithSubject_SourceIsClosed_ThrowsIllegalStateException() throws IOException {
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

    @Test
    void newSource_success() {
        val options = DefaultJwtSource.JwtSourceOptions
                .builder()
                .workloadApiClient(workloadApiClient)
                .initTimeout(Duration.ofSeconds(0))
                .build();
        try {
            JwtSource jwtSource = DefaultJwtSource.newSource(options);
            assertNotNull(jwtSource);
        } catch (SocketEndpointAddressException | JwtSourceException e) {
            fail(e);
        }
    }

    @Test
    void newSource_nullParam() {
        try {
            DefaultJwtSource.newSource(null);
            fail();
        } catch (NullPointerException e) {
            assertEquals("options is marked non-null but is null", e.getMessage());
        } catch (SocketEndpointAddressException | JwtSourceException e) {
            fail();
        }
    }

    @Test
    void newSource_errorFetchingJwtBundles() {
        val options = DefaultJwtSource.JwtSourceOptions
                .builder()
                .workloadApiClient(workloadApiClientErrorStub)
                .spiffeSocketPath("unix:/tmp/test")
                .build();
        try {
            DefaultJwtSource.newSource(options);
            fail();
        } catch (JwtSourceException e) {
            assertEquals("Error creating JWT source", e.getMessage());
            assertEquals("Error fetching JwtBundleSet", e.getCause().getMessage());
        } catch (Exception e) {
            fail();
        }
    }

    @Test
    void newSource_FailsBecauseOfTimeOut() throws Exception {
        try {
            val options = DefaultJwtSource.JwtSourceOptions
                    .builder()
                    .spiffeSocketPath("unix:/tmp/test")
                    .build();
            DefaultJwtSource.newSource(options);
            fail();
        } catch (JwtSourceException e) {
            assertEquals("Error creating JWT source", e.getMessage());
            assertEquals("Timeout waiting for JWT bundles update", e.getCause().getMessage());
        } catch (SocketEndpointAddressException e) {
            fail();
        }
    }

    @Test
    void newSource_DefaultSocketAddress() throws Exception {
        try {
            TestUtils.setEnvironmentVariable(Address.SOCKET_ENV_VARIABLE, "unix:/tmp/test");
            DefaultJwtSource.newSource();
            fail();
        } catch (JwtSourceException e) {
            assertEquals("Error creating JWT source", e.getMessage());
        } catch (SocketEndpointAddressException e) {
            fail();
        }
    }

    @Test
    void newSource_noSocketAddress() throws Exception {
        try {
            // just in case it's defined in the environment
            TestUtils.setEnvironmentVariable(Address.SOCKET_ENV_VARIABLE, "");
            DefaultJwtSource.newSource();
            fail();
        } catch (SocketEndpointAddressException e) {
            fail();
        } catch (IllegalStateException e) {
            assertEquals("Endpoint Socket Address Environment Variable is not set: SPIFFE_ENDPOINT_SOCKET", e.getMessage());
        }
    }
}