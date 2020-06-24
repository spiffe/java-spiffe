package io.spiffe.provider;

import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.workloadapi.X509Source;
import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Utility class to create instances of {@link SSLContext} initialized with a {@link SpiffeKeyManager} and
 * a {@link SpiffeTrustManager} that are backed by the Workload API.
 */
public final class SpiffeSslContextFactory {

    private static final String DEFAULT_SSL_PROTOCOL = "TLSv1.2";

    /**
     * Creates an {@link SSLContext} initialized with a {@link SpiffeKeyManager} and {@link SpiffeTrustManager}
     * that are backed by the Workload API via a {@link X509Source}.
     *
     * @param options {@link SslContextOptions}. The option {@link X509Source} must be not null.
     *                If the option <code>acceptedSpiffeIdsSupplier</code> is not provided, the Set of accepted SPIFFE IDs
     *                is read from the Security or System Property <code>ssl.spiffe.accept</code>.
     *                If the sslProtocol is not provided, the default TLSv1.2 is used.
     * @return an initialized {@link SSLContext}
     * @throws IllegalArgumentException if the {@link X509Source} is not provided in the options
     * @throws NoSuchAlgorithmException if there is a problem creating the SSL context
     * @throws KeyManagementException   if there is a problem initializing the SSL context
     */
    public static SSLContext getSslContext(@NonNull final SslContextOptions options) throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sslContext;
        if (StringUtils.isNotBlank(options.sslProtocol)) {
            sslContext = SSLContext.getInstance(options.sslProtocol);
        } else {
            sslContext = SSLContext.getInstance(DEFAULT_SSL_PROTOCOL);
        }

        if (options.x509Source == null) {
            throw new IllegalArgumentException("x509Source option cannot be null, an X.509 Source must be provided");
        }

        TrustManager[] trustManager;
        if (options.acceptAnySpiffeId) {
            trustManager = new SpiffeTrustManagerFactory().engineGetTrustManagersAcceptAnySpiffeId(options.x509Source);
        } else {
            if (options.acceptedSpiffeIdsSupplier != null) {
                trustManager = new SpiffeTrustManagerFactory().engineGetTrustManagers(options.x509Source, options.acceptedSpiffeIdsSupplier);
            } else {
                trustManager = new SpiffeTrustManagerFactory().engineGetTrustManagers(options.x509Source);
            }
        }

        sslContext.init(
                new SpiffeKeyManagerFactory().engineGetKeyManagers(options.x509Source),
                trustManager,
                null);
        return sslContext;
    }

    /**
     * Options for creating a new {@link SSLContext}.
     * <p>
     * <code>sslProtocol</code> The SSL Protocol. Default: TLSv1.2
     * <p>
     * <code>x509Source</code> A {@link X509Source} that provides the X.509 materials.
     * <p>
     * <code>acceptedSpiffeIdsSupplier</code> A supplier of a set of {@link SpiffeId} that will be accepted for a secure socket connection.
     * <p>
     * <code>acceptAnySpiffeId</code> Flag that indicates that any {@link SpiffeId} will be accepted for a secure socket connection. This config overrules
     * the <code>acceptedSpiffeIdsSupplier</code> property.
     */
    @Data
    public static class SslContextOptions {

        String sslProtocol;
        X509Source x509Source;
        Supplier<Set<SpiffeId>> acceptedSpiffeIdsSupplier;
        boolean acceptAnySpiffeId;

        @Builder
        public SslContextOptions(
                final String sslProtocol,
                final X509Source x509Source,
                final Supplier<Set<SpiffeId>> acceptedSpiffeIdsSupplier,
                final boolean acceptAnySpiffeId) {
            this.x509Source = x509Source;
            this.acceptedSpiffeIdsSupplier = acceptedSpiffeIdsSupplier;
            this.sslProtocol = sslProtocol;
            this.acceptAnySpiffeId = acceptAnySpiffeId;
        }
    }

    private SpiffeSslContextFactory() {
    }
}
