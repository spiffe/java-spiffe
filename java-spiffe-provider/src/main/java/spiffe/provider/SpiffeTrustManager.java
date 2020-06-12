package spiffe.provider;

import spiffe.bundle.BundleSource;
import spiffe.bundle.x509bundle.X509Bundle;
import spiffe.exception.BundleNotFoundException;
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
 * A <code>SpiffeTrustManager</code> is an implementation of a X.509 TrustManager for the SPIFFE Provider.
 * <p>
 * Provides methods to validate the certificate chain using Trusted certs provided by a {@link BundleSource}
 * maintained via the Workload API and the SPIFFE ID using a Supplier of a List of accepted SPIFFE IDs.
 */
public final class SpiffeTrustManager extends X509ExtendedTrustManager {

    private final BundleSource<X509Bundle> x509BundleSource;
    private final Supplier<List<SpiffeId>> acceptedSpiffeIdsSupplier;

    /**
     * Creates a SpiffeTrustManager with a X.509 bundle source used to provide the trusted
     * bundles, and a Supplier of a List of accepted SpiffeIds to be used during peer SVID validation.
     *
     * @param x509BundleSource          an implementation of a {@link BundleSource}
     * @param acceptedSpiffeIdsSupplier a Supplier of a list of accepted SPIFFE IDs.
     */
    public SpiffeTrustManager(BundleSource<X509Bundle> x509BundleSource,
                              Supplier<List<SpiffeId>> acceptedSpiffeIdsSupplier) {
        this.x509BundleSource = x509BundleSource;
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
        validatePeerChain(chain);
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
        validatePeerChain(chain);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    /**
     * {@link #checkClientTrusted(X509Certificate[], String)}
     */
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        checkServerTrusted(chain, authType);
    }

    /**
     * {@link #checkClientTrusted(X509Certificate[], String)}
     */
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        checkClientTrusted(chain, authType);
    }

    /**
     * {@link #checkServerTrusted(X509Certificate[], String)}
     */
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        checkServerTrusted(chain, authType);
    }

    // Check the spiffeId using the checkSpiffeId function and the chain using the bundleSource and a Validator
    private void validatePeerChain(X509Certificate[] chain) throws CertificateException {
        X509SvidValidator.verifySpiffeId(chain[0], acceptedSpiffeIdsSupplier);
        try {
            X509SvidValidator.verifyChain(Arrays.asList(chain), x509BundleSource);
        } catch (BundleNotFoundException e) {
            throw new CertificateException(e.getMessage(), e);
        }
    }
}
