package io.spiffe.workloadapi;

import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.exception.X509SourceException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.svid.x509svid.X509Svid;
import io.spiffe.utils.TestUtils;
import lombok.val;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class DefaultX509SourceTest {

    private DefaultX509Source x509Source;
    private WorkloadApiClientStub workloadApiClient;
    private WorkloadApiClientErrorStub workloadApiClientErrorStub;

    @BeforeEach
    void setUp() throws X509SourceException, SocketEndpointAddressException {
        workloadApiClient = new WorkloadApiClientStub();
        DefaultX509Source.X509SourceOptions options = DefaultX509Source.X509SourceOptions.builder().workloadApiClient(workloadApiClient).build();
        System.setProperty(DefaultJwtSource.TIMEOUT_SYSTEM_PROPERTY, "PT1S");
        x509Source = DefaultX509Source.newSource(options);
        workloadApiClientErrorStub = new WorkloadApiClientErrorStub();
    }

    @AfterEach
    void tearDown() {
        x509Source.close();
    }


    @Test
    void testGetBundleForTrustDomain() {
        try {
            X509Bundle bundle = x509Source.getBundleForTrustDomain(TrustDomain.parse("example.org"));
            assertNotNull(bundle);
            assertEquals(TrustDomain.parse("example.org"), bundle.getTrustDomain());
        } catch (BundleNotFoundException e) {
            fail(e);
        }
    }

    @Test
    void testGetBundleForTrustDomain_nullParam() {
        try {
            x509Source.getBundleForTrustDomain(null);
            fail();
        } catch (NullPointerException e) {
            assertEquals("trustDomain is marked non-null but is null", e.getMessage());
        } catch (BundleNotFoundException e) {
            fail();
        }
    }

    @Test
    void testGetBundleForTrustDomain_SourceIsClosed_ThrowsIllegalStateExceptions() {
        x509Source.close();
        try {
            x509Source.getBundleForTrustDomain(TrustDomain.parse("example.org"));
            fail("exceptions is expected");
        } catch (IllegalStateException e) {
            assertEquals("X.509 bundle source is closed", e.getMessage());
            assertTrue(workloadApiClient.closed);
        } catch (BundleNotFoundException e) {
            fail("not expected exception", e);
        }
    }

    @Test
    void testGetX509Svid() {
        X509Svid x509Svid = x509Source.getX509Svid();
        assertNotNull(x509Svid);
        assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"),x509Svid.getSpiffeId());
    }

    @Test
    void testGetX509Svid_SourceIsClosed_ThrowsIllegalStateException() {
        x509Source.close();
        try {
            x509Source.getX509Svid();
            fail("exceptions is expected");
        } catch (IllegalStateException e) {
            assertEquals("X.509 SVID source is closed", e.getMessage());
        }
    }

    @Test
    void newSource_success() {
        val options = DefaultX509Source.X509SourceOptions
                .builder()
                .workloadApiClient(workloadApiClient)
                .svidPicker((list) -> list.get(0))
                .initTimeout(Duration.ofSeconds(0))
                .build();
        try {
            DefaultX509Source jwtSource = DefaultX509Source.newSource(options);
            assertNotNull(jwtSource);
        } catch (SocketEndpointAddressException | X509SourceException e) {
            fail(e);
        }
    }

    @Test
    void newSource_nullParam() {
        try {
            DefaultX509Source.newSource(null);
            fail();
        } catch (NullPointerException e) {
            assertEquals("options is marked non-null but is null", e.getMessage());
        } catch (SocketEndpointAddressException | X509SourceException e) {
            fail();
        }
    }
    @Test
    void newSource_timeout() throws Exception {
        try {
            val options = DefaultX509Source.X509SourceOptions
                    .builder()
                    .initTimeout(Duration.ofSeconds(1))
                    .spiffeSocketPath("unix:/tmp/test")
                    .build();
            DefaultX509Source.newSource(options);
            fail();
        } catch (X509SourceException e) {
            assertEquals("Error creating X.509 source", e.getMessage());
        } catch (SocketEndpointAddressException e) {
            fail();
        }
    }

    @Test
    void newSource_errorFetchingX509Context() {
        val options = DefaultX509Source.X509SourceOptions
                .builder()
                .workloadApiClient(workloadApiClientErrorStub)
                .spiffeSocketPath("unix:/tmp/test")
                .build();
        try {
            DefaultX509Source.newSource(options);
            fail();
        } catch (X509SourceException e) {
            assertEquals("Error creating X.509 source", e.getMessage());
            assertEquals("Error in X509Context watcher", e.getCause().getMessage());
        } catch (Exception e) {
            fail();
        }
    }

    @Test
    void newSource_noSocketAddress() throws Exception {
        try {
            // just in case the variable is defined in the environment
            TestUtils.setEnvironmentVariable(Address.SOCKET_ENV_VARIABLE, "");
            DefaultX509Source.newSource();
            fail();
        } catch (X509SourceException | SocketEndpointAddressException e) {
            fail();
        } catch (IllegalStateException e) {
            assertEquals("Endpoint Socket Address Environment Variable is not set: SPIFFE_ENDPOINT_SOCKET", e.getMessage());
        }
    }
}