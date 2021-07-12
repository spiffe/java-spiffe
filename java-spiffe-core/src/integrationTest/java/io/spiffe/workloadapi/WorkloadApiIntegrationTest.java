package io.spiffe.workloadapi;

import io.spiffe.bundle.jwtbundle.JwtBundleSet;
import io.spiffe.bundle.x509bundle.X509BundleSet;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.exception.JwtBundleException;
import io.spiffe.exception.JwtSvidException;
import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.exception.X509BundleException;
import io.spiffe.exception.X509ContextException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.svid.jwtsvid.JwtSvid;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

// To run these tests there should be a Workload API running, the SPIFFE_ENDPOINT_SOCKET env variable should be defined,
// and there should be a registration entry with a SPIFFE-ID = 'spiffe://example.org/myservice' and a selector unix:uid with
// the user id used to run the process.
class WorkloadApiIntegrationTest {

    private WorkloadApiClient client;

    @BeforeEach
    void setup() throws SocketEndpointAddressException {
        client = DefaultWorkloadApiClient.newClient();
    }

    @Test
    void testFetchX509Context() throws X509ContextException, BundleNotFoundException {
        X509Context response = client.fetchX509Context();
        Assertions.assertEquals(response.getDefaultSvid().getSpiffeId(), SpiffeId.parse("spiffe://example.org/myservice"));
        Assertions.assertNotNull(response.getX509BundleSet().getBundleForTrustDomain(TrustDomain.of("example.org")));
    }

    @Test
    void testFetchJwtBundles() throws BundleNotFoundException, JwtBundleException {
        JwtBundleSet response = client.fetchJwtBundles();
        Assertions.assertNotNull(response.getBundleForTrustDomain(TrustDomain.of("example.org")));
    }

    @Test
    void testFetchX509Bundles() throws BundleNotFoundException, X509BundleException {
        X509BundleSet response = client.fetchX509Bundles();
        Assertions.assertNotNull(response.getBundleForTrustDomain(TrustDomain.of("example.org")));
    }

    @Test
    void testFetchJwtSvid() throws JwtSvidException {
        JwtSvid response = client.fetchJwtSvid("audience1", "audience2");
        Assertions.assertEquals(response.getSpiffeId(), SpiffeId.parse("spiffe://example.org/myservice"));
        Assertions.assertTrue(response.getAudience().contains("audience1"));
        Assertions.assertTrue(response.getAudience().contains("audience2"));
        Assertions.assertNotNull(response.getToken());
    }

    @Test
    void testValidateJwtSvid() throws JwtSvidException {
        String token = client.fetchJwtSvid("audience1", "audience2").getToken();

        JwtSvid response = client.validateJwtSvid(token, "audience1");
        Assertions.assertEquals(response.getSpiffeId(), SpiffeId.parse("spiffe://example.org/myservice"));
        Assertions.assertTrue(response.getAudience().contains("audience1"));
        Assertions.assertTrue(response.getAudience().contains("audience2"));
    }

    @Test
    void testValidateJwtVid_invalid_audience() throws JwtSvidException {
        String token = client.fetchJwtSvid("audience1", "audience2").getToken();

        try {
            client.validateJwtSvid(token, "other");
            Assertions.fail();
        } catch (JwtSvidException e) {
            Assertions.assertEquals("Error validating JWT SVID", e.getMessage());
        }
    }
}
