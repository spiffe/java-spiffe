package io.spiffe.workloadapi;

import io.spiffe.bundle.x509bundle.X509BundleSet;
import io.spiffe.svid.x509svid.X509Svid;
import lombok.NonNull;
import lombok.Value;

import java.util.List;

/**
 * Represents the X.509 materials that are fetched from the Workload API.
 * <p>
 * Contains a list of {@link X509Svid} and a {@link X509BundleSet}.
 */
@Value
public class X509Context {

    List<X509Svid> x509Svids;
    X509BundleSet x509BundleSet;

    X509Context(final List<X509Svid> x509Svids, final X509BundleSet x509BundleSet) {
        this.x509Svids = x509Svids;
        this.x509BundleSet = x509BundleSet;
    }

    /**
     * Creates a new X509Context from the list of X.509 SVIDs and the X.509 Bundle set.
     *
     * @param x509Svids a list of {@link X509Svid}
     * @param x509BundleSet an instance of {@link X509BundleSet}
     * @return an instance of an X509Context
     */
    public static X509Context of(@NonNull final List<X509Svid> x509Svids, @NonNull final X509BundleSet x509BundleSet) {
        if (x509Svids.size() == 0) {
            throw new IllegalArgumentException("The X.509 Context must have a least one X.509 SVID");
        }
        return new X509Context(x509Svids, x509BundleSet);
    }

    /**
     * Returns the default SVID (the first in the list).
     *
     * @return the default SVID (the first in the list)
     */
    public X509Svid getDefaultSvid() {
        return x509Svids.get(0);
    }
}
