package io.spiffe.workloadapi;

import io.spiffe.bundle.jwtbundle.JwtBundleSet;
import io.spiffe.bundle.x509bundle.X509BundleSet;
import io.spiffe.exception.JwtBundleException;
import io.spiffe.exception.JwtSvidException;
import io.spiffe.exception.X509BundleException;
import io.spiffe.exception.X509ContextException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.svid.jwtsvid.JwtSvid;

import java.io.IOException;
import java.util.List;

public class WorkloadApiClientErrorStub implements WorkloadApiClient {

    @Override
    public X509Context fetchX509Context() throws X509ContextException {
        throw new X509ContextException("Testing exception");
    }

    @Override
    public void watchX509Context(Watcher<X509Context> watcher) {
        watcher.onError(new X509ContextException("Testing exception"));
    }

    @Override
    public X509BundleSet fetchX509Bundles() throws X509BundleException {
        throw new X509BundleException("Testing exception");
    }

    @Override
    public void watchX509Bundles(Watcher<X509BundleSet> watcher) {
        watcher.onError(new X509BundleException("Testing exception"));
    }

    @Override
    public JwtSvid fetchJwtSvid(String audience, final String... extraAudience) throws JwtSvidException {
        throw new JwtSvidException("Testing exception");
    }

    @Override
    public JwtSvid fetchJwtSvid(SpiffeId subject, String audience, final String... extraAudience) throws JwtSvidException {
        throw new JwtSvidException("Testing exception");
    }

    @Override
    public List<JwtSvid> fetchJwtSvids(String audience, String... extraAudience) throws JwtSvidException {
        throw new JwtSvidException("Testing exception");
    }

    @Override
    public List<JwtSvid> fetchJwtSvids(SpiffeId subject, String audience, String... extraAudience) throws JwtSvidException {
        throw new JwtSvidException("Testing exception");
    }

    @Override
    public JwtBundleSet fetchJwtBundles() throws JwtBundleException {
        throw new JwtBundleException("Testing exception");
    }

    @Override
    public JwtSvid validateJwtSvid(String token, String audience) throws JwtSvidException {
        return null;
    }

    @Override
    public void watchJwtBundles(Watcher<JwtBundleSet> watcher) {
        watcher.onError(new JwtBundleException("Testing exception"));
    }

    @Override
    public void close() throws IOException {
    }
}
