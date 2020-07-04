package io.spiffe.workloadapi;

import lombok.NonNull;
import lombok.Value;
import io.spiffe.bundle.x509bundle.X509BundleSet;
import io.spiffe.svid.x509svid.X509Svid;

import java.util.List;

/**
 * Represents the X.509 materials that are fetched from the Workload API.
 * <p>
 * Contains a list of {@link X509Svid} and a {@link X509BundleSet}.
 */
@Value
public class X509Context {

    List<X509Svid> x509Svid;
    X509BundleSet x509BundleSet;

    /**
     * Constructor.
     *
     * @param x509Svid a list of {@link X509Svid}
     * @param x509BundleSet an instance of {@link X509BundleSet}
     */
    public X509Context(@NonNull final List<X509Svid> x509Svid, @NonNull final X509BundleSet x509BundleSet) {
        this.x509Svid = x509Svid;
        this.x509BundleSet = x509BundleSet;
    }

    /**
     * Returns the default SVID (the first in the list).
     *
     * @return the default SVID (the first in the list)
     */
    public X509Svid getDefaultSvid() {
        return x509Svid.get(0);
    }
}
