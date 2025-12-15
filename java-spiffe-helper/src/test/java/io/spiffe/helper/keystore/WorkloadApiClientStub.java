package io.spiffe.helper.keystore;

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
import io.spiffe.workloadapi.Watcher;
import io.spiffe.workloadapi.WorkloadApiClient;
import io.spiffe.workloadapi.X509Context;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Collections;
import java.util.Objects;

public class WorkloadApiClientStub implements WorkloadApiClient {

    final String privateKey = "testdata/svid.key.der";
    final String svid = "testdata/svid.der";
    final String x509Bundle = "testdata/bundle.der";

    @Override
    public X509Context fetchX509Context() {
        return generateX509Context();
    }

    @Override
    public void watchX509Context(Watcher<X509Context> watcher) {
        Objects.requireNonNull(watcher, "watcher must not be null");
        X509Context update = generateX509Context();
        watcher.onUpdate(update);
    }

    @Override
    public X509BundleSet fetchX509Bundles() throws X509BundleException {
        return getX509BundleSet();
    }

    @Override
    public void watchX509Bundles(Watcher<X509BundleSet> watcher) {
        Objects.requireNonNull(watcher, "watcher must not be null");
        X509BundleSet update = getX509BundleSet();
        watcher.onUpdate(update);
    }

    @Override
    public JwtSvid fetchJwtSvid(String audience, String... extraAudience) throws JwtSvidException {
        Objects.requireNonNull(audience, "audience must not be null");
        return null;
    }

    @Override
    public JwtSvid fetchJwtSvid(SpiffeId subject, String audience, String... extraAudience) throws JwtSvidException {
        Objects.requireNonNull(subject, "subject must not be null");
        Objects.requireNonNull(audience, "audience must not be null");
        return null;
    }

    @Override
    public List<JwtSvid> fetchJwtSvids(String audience, String... extraAudience) throws JwtSvidException {
        Objects.requireNonNull(audience, "audience must not be null");
        return null;
    }

    @Override
    public List<JwtSvid> fetchJwtSvids(SpiffeId subject, String audience, String... extraAudience) throws JwtSvidException {
        Objects.requireNonNull(subject, "subject must not be null");
        Objects.requireNonNull(audience, "audience must not be null");
        return null;
    }

    @Override
    public JwtBundleSet fetchJwtBundles() throws JwtBundleException {
        return null;
    }

    @Override
    public JwtSvid validateJwtSvid(String token, String audience) throws JwtSvidException {
        Objects.requireNonNull(token, "token must not be null");
        Objects.requireNonNull(audience, "audience must not be null");
        return null;
    }

    @Override
    public void watchJwtBundles(Watcher<JwtBundleSet> watcher) {
        Objects.requireNonNull(watcher, "watcher must not be null");
    }

    @Override
    public void close() throws IOException {
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
        } catch (IOException | X509BundleException e) {
            throw new RuntimeException(e);
        }
    }

    private X509BundleSet getX509BundleSet() {
        try {
            Path pathBundle = Paths.get(toUri(x509Bundle));
            byte[] bundleBytes = Files.readAllBytes(pathBundle);
            X509Bundle bundle1 = X509Bundle.parse(TrustDomain.parse("example.org"), bundleBytes);
            X509Bundle bundle2 = X509Bundle.parse(TrustDomain.parse("domain.test"), bundleBytes);
            return X509BundleSet.of(Arrays.asList(bundle1, bundle2));
        } catch (IOException | X509BundleException e) {
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
