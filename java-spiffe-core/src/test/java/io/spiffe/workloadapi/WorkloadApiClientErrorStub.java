package io.spiffe.workloadapi;

import io.spiffe.bundle.jwtbundle.JwtBundleSet;
import io.spiffe.bundle.x509bundle.X509BundleSet;
import io.spiffe.exception.JwtBundleException;
import io.spiffe.exception.JwtSvidException;
import io.spiffe.exception.X509BundleException;
import io.spiffe.exception.X509ContextException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.svid.jwtsvid.JwtSvid;
import lombok.NonNull;

import java.io.IOException;

public class WorkloadApiClientErrorStub implements WorkloadApiClient {

    @Override
    public X509Context fetchX509Context() throws X509ContextException {
        throw new X509ContextException("Testing exception");
    }

    @Override
    public void watchX509Context(@NonNull final Watcher<X509Context> watcher) {
        watcher.onError(new X509ContextException("Testing exception"));
    }

    @Override
    public X509BundleSet fetchX509Bundles() throws X509BundleException {
        throw new X509BundleException("Testing exception");
    }

    @Override
    public void watchX509Bundles(@NonNull Watcher<X509BundleSet> watcher) {
        watcher.onError(new X509BundleException("Testing exception"));
    }

    @Override
    public JwtSvid fetchJwtSvid(@NonNull final String audience, final String... extraAudience) throws JwtSvidException {
        throw new JwtSvidException("Testing exception");
    }

    @Override
    public JwtSvid fetchJwtSvid(@NonNull final SpiffeId subject, @NonNull final String audience, final String... extraAudience) throws JwtSvidException {
        throw new JwtSvidException("Testing exception");
    }

    @Override
    public JwtBundleSet fetchJwtBundles() throws JwtBundleException {
        throw new JwtBundleException("Testing exception");
    }

    @Override
    public JwtSvid validateJwtSvid(@NonNull final String token, @NonNull final String audience) throws JwtSvidException {
        return null;
    }

    @Override
    public void watchJwtBundles(@NonNull final Watcher<JwtBundleSet> watcher) {
        watcher.onError(new JwtBundleException("Testing exception"));
    }

    @Override
    public void close() throws IOException {
    }
}
