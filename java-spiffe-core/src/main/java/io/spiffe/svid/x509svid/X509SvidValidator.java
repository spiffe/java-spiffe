package io.spiffe.svid.x509svid;

import io.spiffe.bundle.BundleSource;
import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.internal.CertificateUtils;
import io.spiffe.spiffeid.SpiffeId;
import lombok.NonNull;
import lombok.val;

import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Provides methods to validate a chain of X.509 certificates using an X.509 bundle source.
 */
public class X509SvidValidator {

    /**
     * Verifies that a chain of certificates can be chained to one authority in the given X.509 bundle source.
     *
     * @param chain            a list representing the chain of X.509 certificates to be validated
     * @param x509BundleSource a {@link BundleSource } to provide the authorities
     * @throws CertificateException is the chain cannot be verified with an authority from the X.509 bundle source
     * @throws BundleNotFoundException if no X.509 bundle for the trust domain could be found in the X.509 bundle source
     * @throws NullPointerException if the given chain or 509BundleSource are null
     */
    public static void verifyChain(
            @NonNull final List<X509Certificate> chain,
            @NonNull final BundleSource<X509Bundle> x509BundleSource)
            throws CertificateException, BundleNotFoundException {

        val trustDomain = CertificateUtils.getTrustDomain(chain);
        val x509Bundle = x509BundleSource.getBundleForTrustDomain(trustDomain);

        try {
            CertificateUtils.validate(chain, new ArrayList<>(x509Bundle.getX509Authorities()));
        } catch (CertPathValidatorException e) {
            throw new CertificateException("Cert chain cannot be verified", e);
        }
    }

    /**
     * Checks that the X.509 SVID provided has a SPIFFE ID that is in the Set of accepted SPIFFE IDs supplied.
     *
     * @param x509Certificate            a {@link X509Svid} with a SPIFFE ID to be verified
     * @param acceptedSpiffeIdsSupplier a {@link Supplier} of a Set of SPIFFE IDs that are accepted
     * @throws CertificateException if the SPIFFE ID in x509Certificate is not in the Set supplied by acceptedSpiffeIdsSupplier,
     *                              or if the SPIFFE ID cannot be parsed from the x509Certificate
     * @throws NullPointerException if the given x509Certificate or acceptedSpiffeIdsSupplier are null
     */
    public static void verifySpiffeId(@NonNull final X509Certificate x509Certificate,
                                      @NonNull final Supplier<Set<SpiffeId>> acceptedSpiffeIdsSupplier)
            throws CertificateException {
        val spiffeIdSet = acceptedSpiffeIdsSupplier.get();
        val spiffeId = CertificateUtils.getSpiffeId(x509Certificate);
        if (!spiffeIdSet.contains(spiffeId)) {
            throw new CertificateException(String.format("SPIFFE ID %s in X.509 certificate is not accepted", spiffeId));
        }
    }

    private X509SvidValidator() {
    }
}
