package spiffe.bundle.x509bundle;

import lombok.NonNull;
import lombok.Value;
import lombok.val;
import spiffe.exception.BundleNotFoundException;
import spiffe.internal.CertificateUtils;
import spiffe.spiffeid.TrustDomain;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

/**
 * A <code>X509Bundle</code> represents a collection of trusted X.509 authorities for a trust domain.
 */
@Value
public class X509Bundle implements X509BundleSource {

    TrustDomain trustDomain;
    Set<X509Certificate> x509Authorities;

    private X509Bundle(final TrustDomain trustDomain, final Set<X509Certificate> x509Authorities) {
        this.trustDomain = trustDomain;
        this.x509Authorities = x509Authorities;
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
        val bundleBytes = Files.readAllBytes(bundlePath);
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
}
