package io.spiffe.workloadapi;

import com.nimbusds.jose.jwk.Curve;
import io.spiffe.bundle.jwtbundle.JwtBundle;
import io.spiffe.bundle.jwtbundle.JwtBundleSet;
import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.bundle.x509bundle.X509BundleSet;
import io.spiffe.exception.JwtBundleException;
import io.spiffe.exception.JwtSvidException;
import io.spiffe.exception.X509BundleException;
import io.spiffe.exception.X509SvidException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.svid.jwtsvid.JwtSvid;
import io.spiffe.svid.x509svid.X509Svid;
import io.spiffe.utils.TestUtils;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.util.*;

import static io.spiffe.utils.TestUtils.toUri;

public class WorkloadApiClientStub implements WorkloadApiClient {

    static final Duration JWT_TTL = Duration.ofSeconds(60);
    final String privateKey = "testdata/workloadapi/svid.key.der";
    final String svid = "testdata/workloadapi/svid.der";
    final String x509Bundle = "testdata/workloadapi/bundle.der";
    final String jwtBundle = "testdata/workloadapi/bundle.json";
    final SpiffeId subject = SpiffeId.parse("spiffe://example.org/workload-server");
    final SpiffeId extraSubject = SpiffeId.parse("spiffe://example.org/extra-workload-server");

    int fetchJwtSvidCallCount = 0;

    boolean closed;

    Clock clock = Clock.systemDefaultZone();

    @Override
    public X509Context fetchX509Context() {
        return generateX509Context();
    }

    @Override
    public void watchX509Context(Watcher<X509Context> watcher) {
        X509Context update = generateX509Context();
        watcher.onUpdate(update);
    }

    @Override
    public X509BundleSet fetchX509Bundles() {
        return generateX509BundleSet();
    }

    @Override
    public void watchX509Bundles(Watcher<X509BundleSet> watcher) {
        X509BundleSet x509BundleSet = generateX509BundleSet();
        watcher.onUpdate(x509BundleSet);
    }

    @Override
    public JwtSvid fetchJwtSvid(String audience, final String... extraAudience) throws JwtSvidException {
        fetchJwtSvidCallCount++;
        return generateJwtSvid(subject, audience, extraAudience);
    }

    @Override
    public JwtSvid fetchJwtSvid(SpiffeId subject, String audience, String... extraAudience) throws JwtSvidException {
        fetchJwtSvidCallCount++;
        return generateJwtSvid(subject, audience, extraAudience);
    }

    @Override
    public List<JwtSvid> fetchJwtSvids(String audience, String... extraAudience) throws JwtSvidException {
        fetchJwtSvidCallCount++;
        List<JwtSvid> svids = new ArrayList<>();
        svids.add(generateJwtSvid(subject, audience, extraAudience));
        svids.add(generateJwtSvid(extraSubject, audience, extraAudience));
        return svids;
    }

    @Override
    public List<JwtSvid> fetchJwtSvids(SpiffeId subject, String audience, String... extraAudience) throws JwtSvidException {
        fetchJwtSvidCallCount++;
        List<JwtSvid> svids = new ArrayList<>();
        svids.add(generateJwtSvid(subject, audience, extraAudience));
        return svids;
    }

    @Override
    public JwtBundleSet fetchJwtBundles() throws JwtBundleException {
        return generateJwtBundleSet();
    }

    @Override
    public JwtSvid validateJwtSvid(String token, String audience) throws JwtSvidException {
        return null;
    }

    @Override
    public void watchJwtBundles(Watcher<JwtBundleSet> watcher) {
        JwtBundleSet jwtBundleSet = generateJwtBundleSet();
        watcher.onUpdate(jwtBundleSet);
    }

    private JwtBundleSet generateJwtBundleSet() {
        try {
            Path pathBundle = Paths.get(toUri(jwtBundle));
            byte[] bundleBytes = Files.readAllBytes(pathBundle);
            JwtBundle jwtBundle = JwtBundle.parse(TrustDomain.parse("example.org"), bundleBytes);
            return JwtBundleSet.of(Collections.singleton(jwtBundle));
        } catch (IOException | JwtBundleException | URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    private X509BundleSet generateX509BundleSet() {
        try {
            Path pathBundle = Paths.get(toUri(x509Bundle));
            byte[] bundleBytes = Files.readAllBytes(pathBundle);
            X509Bundle x509Bundle1 = X509Bundle.parse(TrustDomain.parse("example.org"), bundleBytes);
            X509Bundle x509Bundle2 = X509Bundle.parse(TrustDomain.parse("domain.test"), bundleBytes);
            return X509BundleSet.of(Arrays.asList(x509Bundle1, x509Bundle2));
        } catch (IOException | X509BundleException | URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    private JwtSvid generateJwtSvid(SpiffeId subject, String audience, String[] extraAudience) throws JwtSvidException {
        final Set<String> audParam = new HashSet<>();
        audParam.add(audience);
        Collections.addAll(audParam, extraAudience);

        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", subject.toString());
        claims.put("aud", new ArrayList<>(audParam));

        claims.put("iat", new Date(clock.millis()));
        claims.put("exp", new Date(clock.millis() + JWT_TTL.toMillis()));

        KeyPair keyPair = TestUtils.generateECKeyPair(Curve.P_521);

        String token = TestUtils.generateToken(claims, keyPair, "authority1");

        return JwtSvid.parseInsecure(token, audParam, "external");
    }


    @Override
    public void close() throws IOException {
        closed = true;
    }

    private X509Context generateX509Context() {
        X509Svid x509Svid = getX509Svid();
        X509Bundle x509Bundle = getX509Bundle();
        X509BundleSet bundleSet = X509BundleSet.of(Collections.singleton(x509Bundle));
        return X509Context.of(Collections.singletonList(x509Svid), bundleSet);
    }

    private X509Bundle getX509Bundle() {
        try {
            Path pathBundle = Paths.get(toUri(x509Bundle));
            byte[] bundleBytes = Files.readAllBytes(pathBundle);
            return X509Bundle.parse(TrustDomain.parse("example.org"), bundleBytes);
        } catch (IOException | URISyntaxException | X509BundleException e) {
            throw new RuntimeException(e);
        }
    }

    private X509Svid getX509Svid() {
        try {
            Path pathCert = Paths.get(toUri(svid));
            byte[] svidBytes = Files.readAllBytes(pathCert);

            Path pathKey = Paths.get(toUri(privateKey));
            byte[] keyBytes = Files.readAllBytes(pathKey);

            return X509Svid.parseRaw(svidBytes, keyBytes, "internal");
        } catch (X509SvidException | IOException | URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    void resetFetchJwtSvidCallCount() {
        fetchJwtSvidCallCount = 0;
    }

    int getFetchJwtSvidCallCount() {
        return fetchJwtSvidCallCount;
    }

    Clock getClock() {
        return clock;
    }

    void setClock(Clock clock) {
        this.clock = clock;
    }
}
