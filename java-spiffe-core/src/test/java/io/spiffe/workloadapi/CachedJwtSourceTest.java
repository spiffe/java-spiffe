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
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static io.spiffe.workloadapi.WorkloadApiClientStub.JWT_TTL;
import static org.junit.jupiter.api.Assertions.*;

class CachedJwtSourceTest {
    private CachedJwtSource jwtSource;
    private WorkloadApiClientStub workloadApiClient;
    private WorkloadApiClientErrorStub workloadApiClientErrorStub;
    private Clock clock;

    @BeforeEach
    void setUp() throws JwtSourceException, SocketEndpointAddressException {
        workloadApiClient = new WorkloadApiClientStub();
        JwtSourceOptions options = JwtSourceOptions.builder().workloadApiClient(workloadApiClient).build();
        System.setProperty(CachedJwtSource.TIMEOUT_SYSTEM_PROPERTY, "PT1S");
        jwtSource = (CachedJwtSource) CachedJwtSource.newSource(options);
        workloadApiClientErrorStub = new WorkloadApiClientErrorStub();

        clock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        workloadApiClient.setClock(clock);
        jwtSource.setClock(clock);
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
    void testFetchJwtSvidWithSubject_ReturnFromCache() {
        try {
            JwtSvid svid = jwtSource.fetchJwtSvid(SpiffeId.parse("spiffe://example.org/workload-server"), "aud3", "aud2", "aud1");
            assertNotNull(svid);
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svid.getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svid.getAudience());
            assertEquals(1, workloadApiClient.getFetchJwtSvidCallCount());

            // call again to get from cache changing the order of the audiences
            svid = jwtSource.fetchJwtSvid(SpiffeId.parse("spiffe://example.org/workload-server"), "aud1", "aud2", "aud3");
            assertNotNull(svid);
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svid.getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svid.getAudience());
            assertEquals(1, workloadApiClient.getFetchJwtSvidCallCount());

            // call again using different subject
            svid = jwtSource.fetchJwtSvid(SpiffeId.parse("spiffe://example.org/extra-workload-server"), "aud2", "aud3", "aud1");
            assertNotNull(svid);
            assertEquals(SpiffeId.parse("spiffe://example.org/extra-workload-server"), svid.getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svid.getAudience());
            assertEquals(2, workloadApiClient.getFetchJwtSvidCallCount());

            // call again using the same audiences
            svid = jwtSource.fetchJwtSvid(SpiffeId.parse("spiffe://example.org/extra-workload-server"), "aud1", "aud2", "aud3");
            assertNotNull(svid);
            assertEquals(SpiffeId.parse("spiffe://example.org/extra-workload-server"), svid.getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svid.getAudience());
            assertEquals(2, workloadApiClient.getFetchJwtSvidCallCount());
        } catch (JwtSvidException e) {
            fail(e);
        }
    }

    @Test
    void testFetchJwtSvidWithSubject_JwtSvidExpiredInCache() {
        try {
            JwtSvid svid = jwtSource.fetchJwtSvid(SpiffeId.parse("spiffe://example.org/workload-server"), "aud1", "aud2", "aud3");
            assertNotNull(svid);
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svid.getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svid.getAudience());
            assertEquals(1, workloadApiClient.getFetchJwtSvidCallCount());

            // set clock forwards but not enough to expire the JWT SVID in the cache
            jwtSource.setClock(clock.offset(clock, JWT_TTL.dividedBy(2).minus(Duration.ofSeconds(1))));

            // call again to get from cache, fetchJwtSvid call count should not change
            svid = jwtSource.fetchJwtSvid(SpiffeId.parse("spiffe://example.org/workload-server"), "aud1", "aud2", "aud3");
            assertNotNull(svid);
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svid.getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svid.getAudience());
            assertEquals(1, workloadApiClient.getFetchJwtSvidCallCount());

            // set clock to expire the JWT SVID in the cache
            jwtSource.setClock(clock.offset(clock, JWT_TTL.dividedBy(2).plus(Duration.ofSeconds(1))));

            // call again, fetchJwtSvid call count should increase
            svid = jwtSource.fetchJwtSvid(SpiffeId.parse("spiffe://example.org/workload-server"), "aud1", "aud2", "aud3");
            assertNotNull(svid);
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svid.getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svid.getAudience());
            assertEquals(2, workloadApiClient.getFetchJwtSvidCallCount());

        } catch (JwtSvidException e) {
            fail(e);
        }
    }

    @Test
    void testFetchJwtSvidWithSubject_JwtSvidExpiredInCache_MultipleThreads() {
        // test fetchJwtSvid with several threads trying to read and write the cache
        // at the same time, the cache should be updated only once
        try {

            jwtSource.fetchJwtSvid(SpiffeId.parse("spiffe://example.org/workload-server"), "aud1", "aud2", "aud3");
            assertEquals(1, workloadApiClient.getFetchJwtSvidCallCount());

            // set clock to expire the JWT SVID in the cache
            Clock offset = Clock.offset(clock, JWT_TTL.dividedBy(2).plus(Duration.ofSeconds(1)));
            jwtSource.setClock(offset);
            workloadApiClient.setClock(offset);

            // create a thread pool with 10 threads
            ExecutorService executorService = Executors.newFixedThreadPool(10);

            List<Future<JwtSvid>> futures = new ArrayList<>();

            // create 10 tasks to fetch a JWT SVID
            for (int i = 0; i < 10; i++) {
                futures.add(executorService.submit(() -> jwtSource.fetchJwtSvid(SpiffeId.parse("spiffe://example.org/workload-server"), "aud1", "aud2", "aud3")));
            }

            // wait for all tasks to finish
            for (Future<JwtSvid> future : futures) {
                future.get();
            }

            // verify that the cache was updated only once after the JWT SVID expired
            assertEquals(2, workloadApiClient.getFetchJwtSvidCallCount());

        } catch (InterruptedException | ExecutionException | JwtSvidException e) {
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
    void testFetchJwtSvidWithoutSubject_ReturnFromCache() {
        try {
            JwtSvid svid = jwtSource.fetchJwtSvid("aud1", "aud2", "aud3");
            assertNotNull(svid);
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svid.getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svid.getAudience());
            assertEquals(1, workloadApiClient.getFetchJwtSvidCallCount());

            // call again to get from cache changing the order of the audiences, the call count should not change
            svid = jwtSource.fetchJwtSvid("aud3", "aud2", "aud1");
            assertNotNull(svid);
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svid.getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svid.getAudience());
            assertEquals(1, workloadApiClient.getFetchJwtSvidCallCount());

            // call again using different audience, the call count should increase
            svid = jwtSource.fetchJwtSvid("other-audience");
            assertNotNull(svid);
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svid.getSpiffeId());
            assertEquals(Sets.newHashSet("other-audience"), svid.getAudience());
            assertEquals(2, workloadApiClient.getFetchJwtSvidCallCount());
        } catch (JwtSvidException e) {
            fail(e);
        }
    }

    @Test
    void testFetchJwtSvidWithoutSubject_JwtSvidExpiredInCache() {
        try {
            JwtSvid svid = jwtSource.fetchJwtSvid("aud1", "aud2", "aud3");
            assertNotNull(svid);
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svid.getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svid.getAudience());
            assertEquals(1, workloadApiClient.getFetchJwtSvidCallCount());

            // set clock forwards but not enough to expire the JWT SVID in the cache
            jwtSource.setClock(clock.offset(clock, JWT_TTL.dividedBy(2).minus(Duration.ofSeconds(1))));

            // call again to get from cache, fetchJwtSvid call count should not change
            svid = jwtSource.fetchJwtSvid("aud3", "aud2", "aud1");
            assertNotNull(svid);
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svid.getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svid.getAudience());
            assertEquals(1, workloadApiClient.getFetchJwtSvidCallCount());

            // set clock forwards to expire the JWT SVID in the cache
            jwtSource.setClock(clock.offset(clock, JWT_TTL.dividedBy(2).plus(Duration.ofSeconds(1))));

            // call again, fetchJwtSvid call count should increase
            svid = jwtSource.fetchJwtSvid("aud1", "aud2", "aud3");
            assertNotNull(svid);
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svid.getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svid.getAudience());
            assertEquals(2, workloadApiClient.getFetchJwtSvidCallCount());
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
    void testFetchJwtSvidsWithSubject() {
        try {
            List<JwtSvid> svids = jwtSource.fetchJwtSvids(SpiffeId.parse("spiffe://example.org/workload-server"), "aud1", "aud2", "aud3");
            assertNotNull(svids);
            assertEquals(1, svids.size());
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svids.get(0).getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svids.get(0).getAudience());
        } catch (JwtSvidException e) {
            fail(e);
        }
    }

    @Test
    void testFetchJwtSvidsWithSubject_ReturnFromCache() {
        try {
            List<JwtSvid> svids = jwtSource.fetchJwtSvids(SpiffeId.parse("spiffe://example.org/workload-server"), "aud1", "aud2", "aud3");
            assertNotNull(svids);
            assertEquals(1, svids.size());
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svids.get(0).getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svids.get(0).getAudience());
            assertEquals(1, workloadApiClient.getFetchJwtSvidCallCount());

            // call again to get from cache changing the order of the audiences
            svids = jwtSource.fetchJwtSvids(SpiffeId.parse("spiffe://example.org/workload-server"), "aud1", "aud2", "aud3");
            assertNotNull(svids);
            assertEquals(1, svids.size());
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svids.get(0).getSpiffeId());
            assertEquals(Sets.newHashSet("aud3", "aud2", "aud1"), svids.get(0).getAudience());
            assertEquals(1, workloadApiClient.getFetchJwtSvidCallCount());

            // call again using different audience
            svids = jwtSource.fetchJwtSvids(SpiffeId.parse("spiffe://example.org/workload-server"), "other-audience");
            assertNotNull(svids);
            assertEquals(1, svids.size());
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svids.get(0).getSpiffeId());
            assertEquals(Sets.newHashSet("other-audience"), svids.get(0).getAudience());
            assertEquals(2, workloadApiClient.getFetchJwtSvidCallCount());
        } catch (JwtSvidException e) {
            fail(e);
        }
    }

    @Test
    void testFetchJwtSvidsWithoutSubject() {
        try {
            List<JwtSvid> svids = jwtSource.fetchJwtSvids("aud1", "aud2", "aud3");
            assertNotNull(svids);
            assertEquals(svids.size(), 2);
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svids.get(0).getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svids.get(0).getAudience());
            assertEquals(SpiffeId.parse("spiffe://example.org/extra-workload-server"), svids.get(1).getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svids.get(1).getAudience());
        } catch (JwtSvidException e) {
            fail(e);
        }
    }

    @Test
    void testFetchJwtSvidsWithoutSubject_ReturnFromCache() {
        try {
            List<JwtSvid> svids = jwtSource.fetchJwtSvids("aud1", "aud2", "aud3");
            assertNotNull(svids);
            assertEquals(svids.size(), 2);
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svids.get(0).getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svids.get(0).getAudience());
            assertEquals(SpiffeId.parse("spiffe://example.org/extra-workload-server"), svids.get(1).getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svids.get(1).getAudience());
            assertEquals(1, workloadApiClient.getFetchJwtSvidCallCount());

            // call again to get from cache changing the order of the audiences
            svids = jwtSource.fetchJwtSvids("aud2", "aud3", "aud1");
            assertNotNull(svids);
            assertEquals(svids.size(), 2);
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svids.get(0).getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svids.get(0).getAudience());
            assertEquals(SpiffeId.parse("spiffe://example.org/extra-workload-server"), svids.get(1).getSpiffeId());
            assertEquals(Sets.newHashSet("aud1", "aud2", "aud3"), svids.get(1).getAudience());
            assertEquals(1, workloadApiClient.getFetchJwtSvidCallCount());

            // call again using different audience
            svids = jwtSource.fetchJwtSvids("other-audience");
            assertNotNull(svids);
            assertEquals(svids.size(), 2);
            assertEquals(SpiffeId.parse("spiffe://example.org/workload-server"), svids.get(0).getSpiffeId());
            assertEquals(Sets.newHashSet("other-audience"), svids.get(0).getAudience());
            assertEquals(SpiffeId.parse("spiffe://example.org/extra-workload-server"), svids.get(1).getSpiffeId());
            assertEquals(Sets.newHashSet("other-audience"), svids.get(1).getAudience());
            assertEquals(2, workloadApiClient.getFetchJwtSvidCallCount());
        } catch (JwtSvidException e) {
            fail(e);
        }
    }

    @Test
    void testFetchJwtSvids_SourceIsClosed_ThrowsIllegalStateException() throws IOException {
        jwtSource.close();
        try {
            jwtSource.fetchJwtSvids("aud1", "aud2", "aud3");
            fail("expected exception");
        } catch (IllegalStateException e) {
            assertEquals("JWT SVID source is closed", e.getMessage());
            assertTrue(workloadApiClient.closed);
        } catch (JwtSvidException e) {
            fail(e);
        }
    }

    @Test
    void testFetchJwtSvidsWithSubject_SourceIsClosed_ThrowsIllegalStateException() throws IOException {
        jwtSource.close();
        try {
            jwtSource.fetchJwtSvids(SpiffeId.parse("spiffe://example.org/workload-server"), "aud1", "aud2", "aud3");
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
        val options = JwtSourceOptions
                .builder()
                .workloadApiClient(workloadApiClient)
                .initTimeout(Duration.ofSeconds(0))
                .build();
        try {
            JwtSource jwtSource = CachedJwtSource.newSource(options);
            assertNotNull(jwtSource);
        } catch (SocketEndpointAddressException | JwtSourceException e) {
            fail(e);
        }
    }

    @Test
    void newSource_nullParam() {
        try {
            CachedJwtSource.newSource(null);
            fail();
        } catch (NullPointerException e) {
            assertEquals("options is marked non-null but is null", e.getMessage());
        } catch (SocketEndpointAddressException | JwtSourceException e) {
            fail();
        }
    }

    @Test
    void newSource_errorFetchingJwtBundles() {
        val options = JwtSourceOptions
                .builder()
                .workloadApiClient(workloadApiClientErrorStub)
                .spiffeSocketPath("unix:/tmp/test")
                .build();
        try {
            CachedJwtSource.newSource(options);
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
            val options = JwtSourceOptions
                    .builder()
                    .spiffeSocketPath("unix:/tmp/test")
                    .build();
            CachedJwtSource.newSource(options);
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
            CachedJwtSource.newSource();
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
            CachedJwtSource.newSource();
            fail();
        } catch (SocketEndpointAddressException e) {
            fail();
        } catch (IllegalStateException e) {
            assertEquals("Endpoint Socket Address Environment Variable is not set: SPIFFE_ENDPOINT_SOCKET", e.getMessage());
        }
    }
}
