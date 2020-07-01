package io.spiffe.workloadapi;

import com.nimbusds.jose.jwk.Curve;
import io.spiffe.bundle.jwtbundle.JwtBundle;
import io.spiffe.bundle.jwtbundle.JwtBundleSet;
import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.bundle.x509bundle.X509BundleSet;
import io.spiffe.exception.JwtBundleException;
import io.spiffe.exception.JwtSvidException;
import io.spiffe.exception.X509SvidException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.svid.jwtsvid.JwtSvid;
import io.spiffe.svid.x509svid.X509Svid;
import io.spiffe.utils.TestUtils;
import lombok.NonNull;
import lombok.val;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class WorkloadApiClientStub implements WorkloadApiClient {

    final String privateKey = "testdata/workloadapi/svid.key.der";
    final String svid = "testdata/workloadapi/svid.der";
    final String x509Bundle = "testdata/workloadapi/bundle.der";
    final String jwtBundle = "testdata/workloadapi/bundle.json";

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
        val pathBundle = Paths.get(toUri(jwtBundle));
        try {
            byte[] bundleBytes = Files.readAllBytes(pathBundle);
            val jwtBundle = JwtBundle.parse(TrustDomain.of("example.org"), bundleBytes);
            return JwtBundleSet.of(Collections.singleton(jwtBundle));
        } catch (IOException | KeyException | JwtBundleException e) {
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
        return new X509Context(Collections.singletonList(x509Svid), bundleSet);
    }

    private X509Bundle getX509Bundle() {
        try {
            Path pathBundle = Paths.get(toUri(x509Bundle));
            byte[] bundleBytes = Files.readAllBytes(pathBundle);
            return X509Bundle.parse(TrustDomain.of("example.org"), bundleBytes);
        } catch (IOException | CertificateException e) {
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
        } catch (X509SvidException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    private URI toUri(String path) {
        try {
            return Thread.currentThread().getContextClassLoader().getResource(path).toURI();
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
