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
import java.util.List;
import java.util.Optional;

/**
 * A <code>X509Bundle</code> represents a collection of trusted public key materials for a trust domain.
 */
@Value
public class X509Bundle implements X509BundleSource {

    TrustDomain trustDomain;
    List<X509Certificate> x509Roots;

    private X509Bundle(final TrustDomain trustDomain, final List<X509Certificate> x509Roots) {
        this.trustDomain = trustDomain;
        this.x509Roots = x509Roots;
    }

    /**
     * Load loads a Bundle from a file on disk.
     *
     * @param trustDomain a TrustDomain to associate to the bundle
     * @param bundlePath a Path to the file that has the x509Roots
     * @return an instance of X509Bundle with the x509Roots
     * associated to the TrustDomain.
     */
    public static Result<X509Bundle, Throwable> load(@NonNull final TrustDomain trustDomain, @NonNull final Path bundlePath) {
        try {
            val bundleBytes = Files.readAllBytes(bundlePath);

            val x509Certificates = CertificateUtils.generateCertificates(bundleBytes);
            if (x509Certificates.isError()) {
                return Result.error(x509Certificates.getError());
            }

            val x509Bundle = new X509Bundle(trustDomain, x509Certificates.getValue());
            return Result.ok(x509Bundle);
        } catch (IOException e) {
            return Result.error(e);
        }
    }

    /**
     * Parses a bundle from a byte array.
     *
     * @param trustDomain a TrustDomain to associate to the bundle
     * @param bundleBytes an array of bytes that represents the x509Roots
     * @return an instance of X509Bundle with the x509Roots
     * associated to the TrustDomain.
     */
    public static Result<X509Bundle, Throwable> parse(@NonNull final TrustDomain trustDomain, @NonNull final byte[] bundleBytes) {
        val x509Certificates = CertificateUtils.generateCertificates(bundleBytes);
        if (x509Certificates.isError()) {
            return Result.error(x509Certificates.getError());
        }

        val x509Bundle = new X509Bundle(trustDomain, x509Certificates.getValue());
        return Result.ok(x509Bundle);
    }

    @Override
    public Optional<X509Bundle> getX509BundleForTrustDomain(TrustDomain trustDomain) {
        if (this.trustDomain.equals(trustDomain)) {
            return Optional.of(this);
        }
        return Optional.empty();
    }
}
