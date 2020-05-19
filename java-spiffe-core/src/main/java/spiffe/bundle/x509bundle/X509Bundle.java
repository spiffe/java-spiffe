package spiffe.bundle.x509bundle;

import lombok.NonNull;
import lombok.Value;
import lombok.val;
import spiffe.exception.BundleNotFoundException;
import spiffe.internal.CertificateUtils;
import spiffe.spiffeid.TrustDomain;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A <code>X509Bundle</code> represents a collection of trusted X.509 authorities for a trust domain.
 */
@Value
public class X509Bundle implements X509BundleSource {

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
     * Creates a new JWT bundle for a trust domain with X.509 Authorities.
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
     * Loads a X.509 bundle from a file on disk.
     *
     * @param trustDomain a {@link TrustDomain} to associate to the bundle
     * @param bundlePath  a path to the file that has the X.509 authorities
     * @return an instance of {@link X509Bundle} with the X.509 authorities
     * associated to the trust domain.
     *
     * @throws IOException in case of failure accessing the given bundle path
     * @throws CertificateException if the bundle cannot be parsed
     */
    public static X509Bundle load(@NonNull final TrustDomain trustDomain, @NonNull final Path bundlePath) throws IOException, CertificateException {
        byte[] bundleBytes;
        try {
            bundleBytes = Files.readAllBytes(bundlePath);
        } catch (NoSuchFileException e) {
            throw new IOException("Unable to load X.509 bundle file");
        }
        val x509Certificates = CertificateUtils.generateCertificates(bundleBytes);
        val x509CertificateSet = new HashSet<>(x509Certificates);
        return new X509Bundle(trustDomain, x509CertificateSet);
    }

    /**
     * Parses a X095 bundle from an array of bytes.
     *
     * @param trustDomain a {@link TrustDomain} to associate to the X.509 bundle
     * @param bundleBytes an array of bytes that represents the X.509 authorities
     *
     * @return an instance of {@link X509Bundle} with the X.509 authorities
     * associated to the given trust domain
     *
     * @throws CertificateException if the bundle cannot be parsed
     */
    public static X509Bundle parse(@NonNull final TrustDomain trustDomain, @NonNull final byte[] bundleBytes) throws CertificateException {
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
    public X509Bundle getX509BundleForTrustDomain(TrustDomain trustDomain) throws BundleNotFoundException {
        if (this.trustDomain.equals(trustDomain)) {
            return this;
        }
        throw new BundleNotFoundException(String.format("No X509 bundle found for trust domain %s", trustDomain));
    }

    /**
     * Returns the X.509 x509Authorities in the bundle.
     */
    public Set<X509Certificate> getX509Authorities() {
        return new HashSet<>(x509Authorities);
    }

    /**
     * Checks if the given X.509 authority exists in the bundle.
     */
    public boolean hasX509Authority(X509Certificate x509Authority) {
        return x509Authorities.contains(x509Authority);
    }

    /**
     * Adds an X.509 authority to the bundle.
     */
    public void addX509Authority(X509Certificate x509Authority) {
        x509Authorities.add(x509Authority);
    }

    /**
     * Removes an X.509 authority from the bundle.
     */
    public void removeX509Authority(X509Certificate x509Authority) {
        x509Authorities.remove(x509Authority);
    }
}
