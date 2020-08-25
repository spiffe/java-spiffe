package io.spiffe.provider;

import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.workloadapi.DefaultX509Source;
import io.spiffe.workloadapi.X509Source;
import lombok.AccessLevel;
import lombok.Data;
import lombok.NonNull;
import lombok.Setter;
import lombok.val;
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

    private SpiffeSslContextFactory() {
    }

    /**
     * Creates an {@link SSLContext} initialized with a {@link SpiffeKeyManager} and {@link SpiffeTrustManager}
     * that are backed by the Workload API via an {@link DefaultX509Source}.
     *
     * @param options {@link SslContextOptions}. The option {@link DefaultX509Source} must be not null.
     *                If the option <code>acceptedSpiffeIdsSupplier</code> is not provided, the Set of accepted SPIFFE IDs
     *                is read from the Security or System Property <code>ssl.spiffe.accept</code>.
     *                If the sslProtocol is not provided, the default TLSv1.2 is used.
     * @return an initialized {@link SSLContext}
     * @throws IllegalArgumentException if the {@link DefaultX509Source} is not provided in the options
     * @throws NoSuchAlgorithmException if there is a problem creating the SSL context
     * @throws KeyManagementException   if there is a problem initializing the SSL context
     */
    public static SSLContext getSslContext(@NonNull final SslContextOptions options)
            throws NoSuchAlgorithmException, KeyManagementException {

        if (options.x509Source == null) {
            throw new IllegalArgumentException("x509Source option cannot be null, an X.509 Source must be provided");
        }

        if (!options.acceptAnySpiffeId && options.acceptedSpiffeIdsSupplier == null) {
            throw new IllegalArgumentException("SSL context should be configured either with a Supplier " +
                    "of accepted SPIFFE IDs or with acceptAnySpiffeId=true");
        }

        val sslContext = newSslContext(options);
        val trustManagers = newTrustManager(options);
        val keyManagers = new SpiffeKeyManagerFactory().engineGetKeyManagers(options.x509Source);

        sslContext.init(keyManagers, trustManagers, null);
        return sslContext;
    }

    private static TrustManager[] newTrustManager(final SslContextOptions options) {
        if (options.acceptAnySpiffeId) {
            return new SpiffeTrustManagerFactory().engineGetTrustManagersAcceptAnySpiffeId(options.x509Source);
        }

        final TrustManager[] trustManager;
        if (options.acceptedSpiffeIdsSupplier != null) {
            trustManager =
                    new SpiffeTrustManagerFactory()
                            .engineGetTrustManagers(options.x509Source, options.acceptedSpiffeIdsSupplier);
        } else {
            trustManager = new SpiffeTrustManagerFactory().engineGetTrustManagers(options.x509Source);
        }

        return trustManager;
    }

    private static SSLContext newSslContext(final SslContextOptions options) throws NoSuchAlgorithmException {
        if (StringUtils.isBlank(options.sslProtocol)) {
            options.sslProtocol = DEFAULT_SSL_PROTOCOL;
        }
        return SSLContext.getInstance(options.sslProtocol);
    }

    /**
     * Options for creating a new {@link SSLContext}.
     * <p>
     * <code>sslProtocol</code> The SSL Protocol. Default: TLSv1.2
     * <p>
     * <code>x509Source</code> An {@link DefaultX509Source} that provides the X.509 materials.
     * <p>
     * <code>acceptedSpiffeIdsSupplier</code> A supplier of a set of {@link SpiffeId} that will be accepted
     * for a secure socket connection.
     * <p>
     * <code>acceptAnySpiffeId</code> Flag that indicates that any {@link SpiffeId} will be accepted for a
     * secure socket connection. This config overrules the <code>acceptedSpiffeIdsSupplier</code> property.
     */
    @Data
    public static class SslContextOptions {

        @Setter(AccessLevel.NONE)
        private String sslProtocol;

        @Setter(AccessLevel.NONE)
        private X509Source x509Source;

        @Setter(AccessLevel.NONE)
        private Supplier<Set<SpiffeId>> acceptedSpiffeIdsSupplier;

        @Setter(AccessLevel.NONE)
        private boolean acceptAnySpiffeId;

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

        public static SslContextOptionsBuilder builder() {
            return new SslContextOptionsBuilder();
        }

        public static class SslContextOptionsBuilder {
            private String sslProtocol;
            private X509Source x509Source;
            private Supplier<Set<SpiffeId>> acceptedSpiffeIdsSupplier;
            private boolean acceptAnySpiffeId;

            SslContextOptionsBuilder() {
            }

            public SslContextOptionsBuilder sslProtocol(String sslProtocol) {
                this.sslProtocol = sslProtocol;
                return this;
            }

            public SslContextOptionsBuilder x509Source(X509Source x509Source) {
                this.x509Source = x509Source;
                return this;
            }

            public SslContextOptionsBuilder acceptedSpiffeIdsSupplier(Supplier<Set<SpiffeId>> acceptedSpiffeIdsSupplier) {
                this.acceptedSpiffeIdsSupplier = acceptedSpiffeIdsSupplier;
                return this;
            }

            public SslContextOptionsBuilder acceptAnySpiffeId() {
                this.acceptAnySpiffeId = true;
                return this;
            }

            public SslContextOptions build() {
                return new SslContextOptions(sslProtocol, x509Source, acceptedSpiffeIdsSupplier, acceptAnySpiffeId);
            }
        }
    }
}
