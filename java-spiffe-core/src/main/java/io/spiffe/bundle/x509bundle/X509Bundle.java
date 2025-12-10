package io.spiffe.bundle.x509bundle;

import io.spiffe.bundle.BundleSource;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.exception.X509BundleException;
import io.spiffe.internal.CertificateUtils;
import io.spiffe.spiffeid.TrustDomain;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Represents a collection of trusted X.509 authorities for a trust domain.
 */
public final class X509Bundle implements BundleSource<X509Bundle> {

    private final TrustDomain trustDomain;
    private final Set<X509Certificate> x509Authorities;

    /**
     * Creates a new X.509 bundle for a trust domain.
     *
     * @param trustDomain a {@link TrustDomain} to associate to the JwtBundle
     */
    public X509Bundle(final TrustDomain trustDomain) {
        this.trustDomain = Objects.requireNonNull(trustDomain, "trustDomain must not be null");
        this.x509Authorities = ConcurrentHashMap.newKeySet();
    }

    /**
     * Creates a new X.509 bundle for a trust domain with X.509 Authorities.
     *
     * @param trustDomain a {@link TrustDomain} to associate to the JwtBundle
     * @param x509Authorities a Map of X.509 Certificates
     */
    public X509Bundle(TrustDomain trustDomain,
                      Set<X509Certificate> x509Authorities) {
        this.trustDomain = Objects.requireNonNull(trustDomain, "trustDomain must not be null");
        Objects.requireNonNull(x509Authorities, "x509Authorities must not be null");
        this.x509Authorities = ConcurrentHashMap.newKeySet();
        this.x509Authorities.addAll(x509Authorities);
    }

    /**
     * Loads an X.509 bundle from a file on disk.
     *
     * @param trustDomain a {@link TrustDomain} to associate to the bundle
     * @param bundlePath  a path to the file that has the X.509 authorities
     * @return an instance of {@link X509Bundle} with the X.509 authorities
     * associated to the trust domain.
     *
     * @throws X509BundleException in case of failure accessing the given bundle path or the bundle cannot be parsed
     */
    public static X509Bundle load(final TrustDomain trustDomain,
                                  final Path bundlePath) throws X509BundleException {
        Objects.requireNonNull(trustDomain, "trustDomain must not be null");
        Objects.requireNonNull(bundlePath, "bundlePath must not be null");

        final byte[] bundleBytes;
        try {
            bundleBytes = Files.readAllBytes(bundlePath);
        } catch (IOException e) {
            throw new X509BundleException("Unable to load X.509 bundle file", e);
        }

        return parse(trustDomain, bundleBytes);
    }

    /**
     * Parses an X.509 bundle from an array of bytes.
     *
     * @param trustDomain a {@link TrustDomain} to associate to the X.509 bundle
     * @param bundleBytes an array of bytes that represents the X.509 authorities
     *
     * @return an instance of {@link X509Bundle} with the X.509 authorities
     * associated to the given trust domain
     *
     * @throws X509BundleException if the bundle cannot be parsed
     */
    public static X509Bundle parse(final TrustDomain trustDomain,
                                   final byte[] bundleBytes) throws X509BundleException {
        Objects.requireNonNull(trustDomain, "trustDomain must not be null");
        Objects.requireNonNull(bundleBytes, "bundleBytes must not be null");

        List<X509Certificate> x509Certificates = generateX509Certificates(bundleBytes);
        HashSet<X509Certificate> x509CertificateSet = new HashSet<>(x509Certificates);
        return new X509Bundle(trustDomain, x509CertificateSet);
    }

    /**
     * Returns the X.509 bundle associated to the trust domain.
     *
     * @param trustDomain an instance of a {@link TrustDomain}
     * @return the {@link X509Bundle} associated to the given trust domain
     *
     * @throws BundleNotFoundException if no X.509 bundle can be found for the given trust domain
     */
    @Override
    public X509Bundle getBundleForTrustDomain(final TrustDomain trustDomain)
            throws BundleNotFoundException {
        Objects.requireNonNull(trustDomain, "trustDomain must not be null");
        if (this.trustDomain.equals(trustDomain)) {
            return this;
        }
        throw new BundleNotFoundException(
                String.format("No X.509 bundle found for trust domain %s", trustDomain));
    }

    /**
     * Returns the X.509 Authorities in the bundle.
     *
     * @return the X.509 Authorities in the bundle
     */
    public Set<X509Certificate> getX509Authorities() {
        return Collections.unmodifiableSet(x509Authorities);
    }

    /**
     * Checks if the given X.509 authority exists in the bundle.
     *
     * @param x509Authority an X.509 certificate
     * @return boolean true if the x509Authority is present in the X.509 bundle, false otherwise
     */
    public boolean hasX509Authority(final X509Certificate x509Authority) {
        Objects.requireNonNull(x509Authority, "x509Authority must not be null");
        return x509Authorities.contains(x509Authority);
    }

    /**
     * Adds an X.509 authority to the bundle.
     *
     * @param x509Authority an X.509 certificate
     */
    public void addX509Authority(final X509Certificate x509Authority) {
        Objects.requireNonNull(x509Authority, "x509Authority must not be null");
        x509Authorities.add(x509Authority);
    }

    /**
     * Removes an X.509 authority from the bundle.
     *
     * @param x509Authority an X.509 certificate
     */
    public void removeX509Authority(final X509Certificate x509Authority) {
        Objects.requireNonNull(x509Authority, "x509Authority must not be null");
        x509Authorities.remove(x509Authority);
    }

    private static List<X509Certificate> generateX509Certificates(byte[] bundleBytes)
            throws X509BundleException {
        Objects.requireNonNull(bundleBytes, "bundleBytes must not be null");
        try {
            return CertificateUtils.generateCertificates(bundleBytes);
        } catch (CertificateParsingException e) {
            throw new X509BundleException(
                    "Bundle certificates could not be parsed from bundle path", e);
        }
    }

    public TrustDomain getTrustDomain() {
        return trustDomain;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof X509Bundle)) return false;
        X509Bundle that = (X509Bundle) o;
        return Objects.equals(trustDomain, that.trustDomain) &&
                Objects.equals(x509Authorities, that.x509Authorities);
    }

    @Override
    public int hashCode() {
        return Objects.hash(trustDomain, x509Authorities);
    }

    @Override
    public String toString() {
        return "X509Bundle{" +
                "trustDomain=" + trustDomain +
                ", x509Authorities=" + x509Authorities +
                '}';
    }
}
