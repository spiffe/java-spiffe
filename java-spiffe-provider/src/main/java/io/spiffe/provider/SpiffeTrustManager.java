package io.spiffe.provider;

import io.spiffe.bundle.BundleSource;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.svid.x509svid.X509SvidValidator;
import lombok.NonNull;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;

/**
 * Implementation of a X.509 TrustManager for the SPIFFE Provider.
 * <p>
 * Provides methods to validate the X.509 certificate chain using trusted certs provided by a {@link BundleSource}
 * maintained via the Workload API and to verify the SPIFFE ID against a List of accepted SPIFFE IDs provided by a Supplier.
 */
public final class SpiffeTrustManager extends X509ExtendedTrustManager {

    private final BundleSource<X509Bundle> x509BundleSource;
    private final Supplier<List<SpiffeId>> acceptedSpiffeIdsSupplier;
    private final boolean acceptAnySpiffeId;

    /**
     * Constructor.
     * <p>
     * Creates a SpiffeTrustManager with a X.509 bundle source used to provide the trusted bundles,
     * and a {@link Supplier} of a List of accepted {@link SpiffeId} to be used during peer SVID validation.
     *
     * @param x509BundleSource          an implementation of a {@link BundleSource}
     * @param acceptedSpiffeIdsSupplier a {@link Supplier} of a list of accepted SPIFFE IDs.
     */
    public SpiffeTrustManager(@NonNull final BundleSource<X509Bundle> x509BundleSource,
                              @NonNull final Supplier<List<SpiffeId>> acceptedSpiffeIdsSupplier) {
        this.x509BundleSource = x509BundleSource;
        this.acceptedSpiffeIdsSupplier = acceptedSpiffeIdsSupplier;
        this.acceptAnySpiffeId = false;
    }

    /**
     * Constructor.
     * <p>
     * Creates a SpiffeTrustManager with a X.509 bundle source used to provide the trusted bundles,
     * and a flag to indicate that any SPIFFE ID will be accepted.
     *
     * @param x509BundleSource  an implementation of a {@link BundleSource}
     * @param acceptAnySpiffeId a Supplier of a list of accepted SPIFFE IDs.
     */
    public SpiffeTrustManager(@NonNull final BundleSource<X509Bundle> x509BundleSource,
                              final boolean acceptAnySpiffeId) {
        this.x509BundleSource = x509BundleSource;
        this.acceptedSpiffeIdsSupplier = ArrayList::new;
        this.acceptAnySpiffeId = acceptAnySpiffeId;
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
    public void checkClientTrusted(@NonNull final X509Certificate[] chain, final String authType) throws CertificateException {
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
    public void checkServerTrusted(@NonNull final X509Certificate[] chain, final String authType) throws CertificateException {
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
    public void checkClientTrusted(@NonNull final X509Certificate[] chain, final String authType, final Socket socket) throws CertificateException {
        checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(@NonNull final X509Certificate[] chain, final String authType, final Socket socket) throws CertificateException {
        checkServerTrusted(chain, authType);
    }

    /**
     * {@link #checkClientTrusted(X509Certificate[], String)}
     */
    @Override
    public void checkClientTrusted(@NonNull X509Certificate[] chain, final String authType, final SSLEngine sslEngine) throws CertificateException {
        checkClientTrusted(chain, authType);
    }

    /**
     * {@link #checkServerTrusted(X509Certificate[], String)}
     */
    @Override
    public void checkServerTrusted(@NonNull X509Certificate[] chain, final String authType, final SSLEngine sslEngine) throws CertificateException {
        checkServerTrusted(chain, authType);
    }

    // Check that the SPIFFE ID in the peer's certificate is accepted and the chain can be validated with a root CA in the bundle source
    private void validatePeerChain(X509Certificate ...chain) throws CertificateException {
        if (!acceptAnySpiffeId) {
            X509SvidValidator.verifySpiffeId(chain[0], acceptedSpiffeIdsSupplier);
        }

        try {
            X509SvidValidator.verifyChain(Arrays.asList(chain), x509BundleSource);
        } catch (BundleNotFoundException e) {
            throw new CertificateException(e.getMessage(), e);
        }
    }
}
