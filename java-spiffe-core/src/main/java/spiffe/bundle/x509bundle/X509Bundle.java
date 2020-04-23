package spiffe.bundle.x509bundle;

import lombok.NonNull;
import lombok.Value;
import lombok.val;
import spiffe.internal.CertificateUtils;
import spiffe.result.Result;
import spiffe.spiffeid.TrustDomain;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
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
     * Load loads a Bundle from a file on disk.
     *
     * @param trustDomain a TrustDomain to associate to the bundle
     * @param bundlePath a Path to the file that has the X509 Authorities
     * @return an instance of X509Bundle with the X509 Authorities
     * associated to the TrustDomain.
     */
    public static Result<X509Bundle, String> load(@NonNull final TrustDomain trustDomain, @NonNull final Path bundlePath) {
        try {
            val bundleBytes = Files.readAllBytes(bundlePath);

            val x509Certificates = CertificateUtils.generateCertificates(bundleBytes);
            if (x509Certificates.isError()) {
                return Result.error(x509Certificates.getError());
            }

            val x509CertificateSet = new HashSet<>(x509Certificates.getValue());
            val x509Bundle = new X509Bundle(trustDomain, x509CertificateSet);
            return Result.ok(x509Bundle);
        } catch (IOException e) {
            return Result.error("Error loading X509Bundle from path %s: %s", bundlePath, e.getMessage());
        }
    }

    /**
     * Parses a bundle from a byte array.
     *
     * @param trustDomain a TrustDomain to associate to the bundle
     * @param bundleBytes an array of bytes that represents the X509 Authorities
     * @return an instance of X509Bundle with the X509 Authorities
     * associated to the TrustDomain.
     */
    public static Result<X509Bundle, String> parse(@NonNull final TrustDomain trustDomain, @NonNull final byte[] bundleBytes) {
        val x509Certificates = CertificateUtils.generateCertificates(bundleBytes);
        if (x509Certificates.isError()) {
            return Result.error(x509Certificates.getError());
        }

        val x509CertificateSet = new HashSet<>(x509Certificates.getValue());
        val x509Bundle = new X509Bundle(trustDomain, x509CertificateSet);
        return Result.ok(x509Bundle);
    }

    @Override
    public Result<X509Bundle, String> getX509BundleForTrustDomain(TrustDomain trustDomain) {
        if (this.trustDomain.equals(trustDomain)) {
            return Result.ok(this);
        }
        return Result.error("No X509 bundle for trust domain %s", trustDomain);
    }
}
