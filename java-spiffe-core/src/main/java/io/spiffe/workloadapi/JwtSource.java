package io.spiffe.workloadapi;

import io.spiffe.bundle.BundleSource;
import io.spiffe.bundle.jwtbundle.JwtBundle;
import io.spiffe.svid.jwtsvid.JwtSvidSource;

import java.io.Closeable;

/**
 * Source of JWT SVIDs and Bundles.
 * @see JwtSvidSource
 * @see BundleSource
 * @see JwtBundle
 */
public interface JwtSource extends JwtSvidSource, BundleSource<JwtBundle>, Closeable {
}
