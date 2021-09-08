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
import lombok.NonNull;
import lombok.val;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static io.spiffe.utils.TestUtils.toUri;

public class WorkloadApiClientStub implements WorkloadApiClient {

    final String privateKey = "testdata/workloadapi/svid.key.der";
    final String svid = "testdata/workloadapi/svid.der";
    final String x509Bundle = "testdata/workloadapi/bundle.der";
    final String jwtBundle = "testdata/workloadapi/bundle.json";
    final SpiffeId subject = SpiffeId.parse("spiffe://example.org/workload-server");

    boolean closed;

    @Override
    public X509Context fetchX509Context() {
        return generateX509Context();
    }

    @Override
    public void watchX509Context(@NonNull final Watcher<X509Context> watcher) {
        val update = generateX509Context();
        watcher.onUpdate(update);
    }

    @Override
    public X509BundleSet fetchX509Bundles() {
        return generateX509BundleSet();
    }

    @Override
    public void watchX509Bundles(@NonNull Watcher<X509BundleSet> watcher) {
        val x509BundleSet = generateX509BundleSet();
        watcher.onUpdate(x509BundleSet);
    }

    @Override
    public JwtSvid fetchJwtSvid(@NonNull final String audience, final String... extraAudience) throws JwtSvidException {
        return generateJwtSvid(subject, audience, extraAudience);
    }

    @Override
    public JwtSvid fetchJwtSvid(@NonNull final SpiffeId subject, @NonNull final String audience, final String... extraAudience) throws JwtSvidException {
        return generateJwtSvid(subject, audience, extraAudience);
    }

    @Override
    public JwtBundleSet fetchJwtBundles() throws JwtBundleException {
        return generateJwtBundleSet();
    }

    @Override
    public JwtSvid validateJwtSvid(@NonNull final String token, @NonNull final String audience) throws JwtSvidException {
        return null;
    }

    @Override
    public void watchJwtBundles(@NonNull final Watcher<JwtBundleSet> watcher) {
        val jwtBundleSet = generateJwtBundleSet();
        watcher.onUpdate(jwtBundleSet);
    }

    private JwtBundleSet generateJwtBundleSet() {
        try {
            val pathBundle = Paths.get(toUri(jwtBundle));
            byte[] bundleBytes = Files.readAllBytes(pathBundle);
            val jwtBundle = JwtBundle.parse(TrustDomain.parse("example.org"), bundleBytes);
            return JwtBundleSet.of(Collections.singleton(jwtBundle));
        } catch (IOException | JwtBundleException | URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    private X509BundleSet generateX509BundleSet() {
        try {
            val pathBundle = Paths.get(toUri(x509Bundle));
            byte[] bundleBytes = Files.readAllBytes(pathBundle);
            val x509Bundle1 = X509Bundle.parse(TrustDomain.parse("example.org"), bundleBytes);
            val x509Bundle2 = X509Bundle.parse(TrustDomain.parse("domain.test"), bundleBytes);
            return X509BundleSet.of(Arrays.asList(x509Bundle1, x509Bundle2));
        } catch (IOException | X509BundleException | URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    private JwtSvid generateJwtSvid(final @NonNull SpiffeId subject, final @NonNull String audience, final String[] extraAudience) throws JwtSvidException {
        final Set<String> audParam = new HashSet<>();
        audParam.add(audience);
        Collections.addAll(audParam, extraAudience);

        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", subject.toString());
        claims.put("aud", new ArrayList<>(audParam));
        Date expiration = new Date(System.currentTimeMillis() + 3600000);
        claims.put("exp", expiration);

        KeyPair keyPair = TestUtils.generateECKeyPair(Curve.P_521);

        String token = TestUtils.generateToken(claims, keyPair, "authority1");

        return JwtSvid.parseInsecure(token, audParam);
    }


    @Override
    public void close() throws IOException {
        closed = true;
    }

    private X509Context generateX509Context() {
        val x509Svid = getX509Svid();
        val x509Bundle = getX509Bundle();
        val bundleSet = X509BundleSet.of(Collections.singleton(x509Bundle));
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

            return X509Svid.parseRaw(svidBytes, keyBytes);
        } catch (X509SvidException | IOException | URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }
}
