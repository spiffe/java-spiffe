package spiffe.provider;

import lombok.val;
import spiffe.bundle.x509bundle.X509BundleSource;
import spiffe.internal.CertificateUtils;
import spiffe.result.Result;
import spiffe.spiffeid.SpiffeId;
import spiffe.svid.x509svid.X509SvidValidator;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;

/**
 * A <code>SpiffeTrustManager</code> is an implementation of a X509 TrustManager for the SPIFFE Provider.
 * <p>
 * Provides methods to validate the certificate chain using Trusted certs provided by a {@link X509BundleSource}
 * maintained via the Workload API and the SPIFFE ID using a Supplier of a List of accepted SPIFFE IDs.
 */
public final class SpiffeTrustManager extends X509ExtendedTrustManager {

    private final X509BundleSource x509BundleSource;
    private final Supplier<Result<List<SpiffeId>, String>> acceptedSpiffeIdsSupplier;

    /**
     * Creates a SpiffeTrustManager with a X509BundleSource used to provide the trusted
     * bundles, and a Supplier of a List of accepted SpiffeIds to be used during peer SVID validation.
     *
     * @param X509BundleSource an implementation of a {@link X509BundleSource}
     * @param acceptedSpiffeIdsSupplier a Supplier of a list of accepted SPIFFE IDs.
     */
    public SpiffeTrustManager(X509BundleSource X509BundleSource,
                              Supplier<Result<List<SpiffeId>, String>> acceptedSpiffeIdsSupplier) {
        this.x509BundleSource = X509BundleSource;
        this.acceptedSpiffeIdsSupplier = acceptedSpiffeIdsSupplier;
    }

    /**
     * Given the partial or complete certificate chain provided by the peer,
     * build a certificate path to a trusted root and return if it can be validated
     * and is trusted for Client SSL authentication based on the authentication type.
     * <p>
     * Throws a {@link CertificateException} if the chain cannot be chained to a trusted bundled,
     * or if the SPIFFE ID in the chain is not in the list of accepted SPIFFE IDs.
     *
     * @param chain    the peer certificate chain
     * @param authType not used
     * @throws CertificateException when the chain or the SPIFFE ID presented are not trusted.
     */
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        val result = validatePeerChain(chain);
        if (result.isError()) {
            throw new CertificateException(result.getError());
        }
    }

    /**
     * Given the partial or complete certificate chain provided by the peer,
     * build a certificate path to a trusted root and return if it can be validated
     * and is trusted for Server SSL authentication based on the authentication type.
     * <p>
     * Throws a {@link CertificateException} if the chain cannot be chained to a trusted bundled,
     * or if the SPIFFE ID in the chain is not in the list of accepted SPIFFE IDs.
     *
     * @param chain    the peer certificate chain
     * @param authType not used
     * @throws CertificateException when the chain or the SPIFFE ID presented are not trusted.
     */
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        val result = validatePeerChain(chain);
        if (result.isError()) {
            throw new CertificateException(result.getError());
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    /** {@link #checkClientTrusted(X509Certificate[], String)} */
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        checkServerTrusted(chain, authType);
    }

    /** {@link #checkClientTrusted(X509Certificate[], String)} */
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        checkClientTrusted(chain, authType);
    }

    /** {@link #checkServerTrusted(X509Certificate[], String)} */
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        checkServerTrusted(chain, authType);
    }

    // Check the spiffeId using the checkSpiffeId function and the chain using the bundleSource and a Validator
    private Result<Boolean, String> validatePeerChain(X509Certificate[] chain) {
        val spiffeId = CertificateUtils.getSpiffeId(chain[0]);
        if (spiffeId.isError()) {
            return Result.error(spiffeId.getError());
        }

        return X509SvidValidator
                .verifySpiffeId(
                        spiffeId.getValue(),
                        acceptedSpiffeIdsSupplier)
                .thenApply(
                        X509SvidValidator::verifyChain,
                        Arrays.asList(chain),
                        x509BundleSource
                );
    }
}
