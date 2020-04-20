package spiffe.svid.x509svid;

import lombok.NonNull;
import lombok.val;
import org.apache.commons.lang3.exception.ExceptionUtils;
import spiffe.bundle.x509bundle.X509BundleSource;
import spiffe.internal.CertificateUtils;
import spiffe.result.Result;
import spiffe.spiffeid.SpiffeId;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

/**
 * A <code>X509SvidValidator</code> provides methods to validate
 * a chain of X509 Certificates using an X509BundleSource.
 */
public class X509SvidValidator {

    /**
     * Verifies that a chain of certificate can be chained to one trustedCert in the x509BundleSource.
     *
     * @param chain a chain of X509 Certificates to be validated
     * @param x509BundleSource a {@link X509BundleSource }to provide the trusted bundle certs
     *
     * @return a Result object conveying the result of the verification. If the chain can be verified with
     * a trusted bundle, it returns an Ok(true), otherwise returns an Error with a String message.
     */
    public static Result<Boolean, String> verifyChain(
            @NonNull List<X509Certificate> chain,
            @NonNull X509BundleSource x509BundleSource) {
        val trustDomain = CertificateUtils.getTrustDomain(chain);
        if (trustDomain.isError()) {
            return Result.error(trustDomain.getError());
        }

        val x509Bundle = x509BundleSource.getX509BundleForTrustDomain(trustDomain.getValue());

        if (x509Bundle.isError()) {
            return Result.error(String.format("No X509 Bundle found for the Trust Domain %s", trustDomain.getValue()));
        }

        val result = CertificateUtils.validate(chain, new ArrayList<>(x509Bundle.getValue().getX509Roots()));
        if (result.isError()) {
            return Result.error(ExceptionUtils.getRootCauseMessage(result.getError()));
        }

        return Result.ok(true);
    }

    /**
     * Checks that the Certificate provided has a SPIFFE ID that is in the list of acceptedSpiffeIds supplied.
     *
     * @param spiffeId a SPIFFE ID to be verified
     * @param acceptedSpiffedIdsSupplier a Supplier of a List os SPIFFE IDs that are accepted
     *
     * @return an {@link spiffe.result.Ok} with true if the SPIFFE ID is in the list,
     * an {@link spiffe.result.Error} containing en error message if the SPIFFE ID is not in the list
     * or if there's en error getting the list.
     */
    public static Result<Boolean, String> verifySpiffeId(SpiffeId spiffeId, Supplier<Result<List<SpiffeId>, String>> acceptedSpiffedIdsSupplier) {
        if (acceptedSpiffedIdsSupplier.get().isError()) {
            return Result.error("Error getting list of accepted SPIFFE IDs");
        }

        val spiffeIdList = acceptedSpiffedIdsSupplier.get();
        if (spiffeIdList.isError()) {
            return Result.error(spiffeIdList.getError());
        }

        if (spiffeIdList.getValue().contains(spiffeId)) {
            return Result.ok(true);
        }

        return Result.error(String.format("SPIFFE ID '%s' is not accepted.", spiffeId));
    }
}
