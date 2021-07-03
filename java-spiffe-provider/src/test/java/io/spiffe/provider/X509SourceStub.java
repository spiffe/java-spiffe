package io.spiffe.provider;

import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.exception.X509BundleException;
import io.spiffe.exception.X509SvidException;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.svid.x509svid.X509Svid;
import io.spiffe.workloadapi.X509Source;
import lombok.NonNull;

import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;

import static io.spiffe.utils.TestUtils.toUri;

public class X509SourceStub implements X509Source {

    private final X509Svid svid;
    private final X509Bundle bundle;

    public X509SourceStub() {
        try {
            Path cert = Paths.get(toUri("testdata/cert.pem"));
            Path key = Paths.get(toUri("testdata/key.pem"));
            svid = X509Svid.load(cert, key);
            bundle = X509Bundle.load(
                    TrustDomain.parse("spiffe://example.org"),
                    Paths.get(toUri("testdata/bundle.pem")));
        } catch (X509SvidException | URISyntaxException | X509BundleException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public X509Bundle getBundleForTrustDomain(@NonNull TrustDomain trustDomain) throws BundleNotFoundException {
        if (TrustDomain.parse("example.org").equals(trustDomain)) {
            return bundle;
        }
        throw new BundleNotFoundException("trustDomain not found");
    }

    @Override
    public X509Svid getX509Svid() {
        return svid;
    }

    @Override
    public void close() {
    }
}
