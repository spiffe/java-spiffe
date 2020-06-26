package io.spiffe.bundle.x509bundle;

import io.spiffe.bundle.BundleSource;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.internal.CertificateUtils;
import io.spiffe.spiffeid.TrustDomain;
import lombok.NonNull;
import lombok.Value;
import lombok.val;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Represents a collection of trusted X.509 authorities for a trust domain.
 */
@Value
public class X509Bundle implements BundleSource<X509Bundle> {

    TrustDomain trustDomain;
    Set<X509Certificate> x509Authorities;

    /**
     * Creates a new X.509 bundle for a trust domain.
     *
     * @param trustDomain a {@link TrustDomain} to associate to the JwtBundle
     */
    public X509Bundle(@NonNull final TrustDomain trustDomain) {
        this.trustDomain = trustDomain;
        this.x509Authorities = ConcurrentHashMap.newKeySet();
    }

    /**
     * Creates a new X.509 bundle for a trust domain with X.509 Authorities.
     *
     * @param trustDomain a {@link TrustDomain} to associate to the JwtBundle
     * @param x509Authorities a Map of X.509 Certificates
     */
    public X509Bundle(@NonNull final TrustDomain trustDomain, @NonNull final Set<X509Certificate> x509Authorities) {
        this.trustDomain = trustDomain;
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
     * @throws IOException in case of failure accessing the given bundle path
     * @throws CertificateException if the bundle cannot be parsed
     */
    public static X509Bundle load(@NonNull final TrustDomain trustDomain, @NonNull final Path bundlePath)
            throws IOException, CertificateException {

        final byte[] bundleBytes;
        try {
            bundleBytes = Files.readAllBytes(bundlePath);
        } catch (NoSuchFileException e) {
            throw new IOException("Unable to load X.509 bundle file", e);
        }

        val x509Certificates = CertificateUtils.generateCertificates(bundleBytes);
        val x509CertificateSet = new HashSet<>(x509Certificates);
        return new X509Bundle(trustDomain, x509CertificateSet);
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
     * @throws CertificateException if the bundle cannot be parsed
     */
    public static X509Bundle parse(@NonNull final TrustDomain trustDomain, @NonNull final byte[] bundleBytes)
            throws CertificateException {
        val x509Certificates = CertificateUtils.generateCertificates(bundleBytes);
        val x509CertificateSet = new HashSet<>(x509Certificates);
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
    public X509Bundle getBundleForTrustDomain(@NonNull final TrustDomain trustDomain) throws BundleNotFoundException {
        if (this.trustDomain.equals(trustDomain)) {
            return this;
        }
        throw new BundleNotFoundException(String.format("No X.509 bundle found for trust domain %s", trustDomain));
    }

    /**
     * @return the X.509 Authorities in the bundle.
     */
    public Set<X509Certificate> getX509Authorities() {
        return Collections.unmodifiableSet(x509Authorities);
    }

    /**
     * Checks if the given X.509 authority exists in the bundle.
     * @param x509Authority an X.509 certificate
     * @return boolean true if the x509Authority is present in the X.509 bundle, false otherwise
     */
    public boolean hasX509Authority(@NonNull final X509Certificate x509Authority) {
        return x509Authorities.contains(x509Authority);
    }

    /**
     * Adds an X.509 authority to the bundle.
     * @param x509Authority an X.509 certificate
     */
    public void addX509Authority(@NonNull final X509Certificate x509Authority) {
        x509Authorities.add(x509Authority);
    }

    /**
     * Removes an X.509 authority from the bundle.
     * @param x509Authority an X.509 certificate
     */
    public void removeX509Authority(@NonNull final X509Certificate x509Authority) {
        x509Authorities.remove(x509Authority);
    }
}
