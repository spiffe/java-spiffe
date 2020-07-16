package io.spiffe.workloadapi;

import io.spiffe.bundle.BundleSource;
import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.svid.x509svid.X509SvidSource;

import java.io.Closeable;

/**
 * Source of X.509 SVIDs and Bundles.
 */
public interface X509Source extends X509SvidSource, BundleSource<X509Bundle>, Closeable {
}
