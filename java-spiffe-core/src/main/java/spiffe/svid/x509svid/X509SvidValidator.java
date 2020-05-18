package spiffe.svid.x509svid;

import lombok.NonNull;
import lombok.val;
import spiffe.bundle.x509bundle.X509BundleSource;
import spiffe.exception.BundleNotFoundException;
import spiffe.internal.CertificateUtils;
import spiffe.spiffeid.SpiffeId;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

/**
 * A <code>X509SvidValidator</code> provides methods to validate
 * a chain of X.509 certificates using an X.509 bundle source.
 */
public class X509SvidValidator {

    /**
     * Verifies that a chain of certificates can be chained to one authority in the given X.509 bundle source.
     *
     * @param chain a list representing the chain of X.509 certificates to be validated
     * @param x509BundleSource a {@link X509BundleSource } to provide the authorities
     *
     * @throws CertificateException is the chain cannot be verified with an authority from the X.509 bundle source
     * @throws NullPointerException if the given chain or 509BundleSource are null
     */
    public static void verifyChain(
            @NonNull List<X509Certificate> chain,
            @NonNull X509BundleSource x509BundleSource) throws CertificateException, BundleNotFoundException {

        val trustDomain = CertificateUtils.getTrustDomain(chain);
        val x509Bundle = x509BundleSource.getX509BundleForTrustDomain(trustDomain);

        try {
            CertificateUtils.validate(chain, new ArrayList<>(x509Bundle.getX509Authorities()));
        } catch (CertPathValidatorException e) {
            throw new CertificateException("Cert chain cannot be verified", e);
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            throw new CertificateException(e.getMessage(), e);
        }
    }

    /**
     * Checks that the X.509 SVID provided has a SPIFFE ID that is in the list of accepted SPIFFE IDs supplied.
     *
     * @param x509Certificate a {@link X509Svid} with a SPIFFE ID to be verified
     * @param acceptedSpiffedIdsSupplier a {@link Supplier} of a list os SPIFFE IDs that are accepted
     *
     * @throws CertificateException is the SPIFFE ID in x509Certificate is not in the list supplied by acceptedSpiffedIdsSupplier,
     * or if the SPIFFE ID cannot be parsed from the x509Certificate
     * @throws NullPointerException if the given x509Certificate or acceptedSpiffedIdsSupplier are null
     */
    public static void verifySpiffeId(@NonNull X509Certificate x509Certificate,
                                      @NonNull Supplier<List<SpiffeId>> acceptedSpiffedIdsSupplier)
            throws CertificateException {
        val spiffeIdList = acceptedSpiffedIdsSupplier.get();
        val spiffeId = CertificateUtils.getSpiffeId(x509Certificate);
        if (!spiffeIdList.contains(spiffeId)) {
            throw new CertificateException(String.format("SPIFFE ID %s in X.509 certificate is not accepted", spiffeId));
        }
    }

    private X509SvidValidator() {}
}
