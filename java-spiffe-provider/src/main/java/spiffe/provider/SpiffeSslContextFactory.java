package spiffe.provider;

import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import spiffe.result.Result;
import spiffe.spiffeid.SpiffeId;
import spiffe.workloadapi.X509Source;

import javax.net.ssl.SSLContext;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.function.Supplier;

/**
 * Utility class to create instances of {@link SSLContext} initialized
 * with a {@link SpiffeKeyManager} and a {@link SpiffeTrustManager} that
 * are backed by the Workload API.
 */
public final class SpiffeSslContextFactory {

    private static final String DEFAULT_SSL_PROTOCOL = "TLSv1.2";

    /**
     * Creates an SSLContext initialized with a SPIFFE KeyManager and TrustManager that are backed by
     * the Workload API via a X509Source.
     *
     * @param options {@link SslContextOptions}. The option {@link X509Source} must be not null.
     *                If the option acceptedSpiffeIdsSupplier is not provided, the list of accepted SPIFFE IDs
     *                is read from the Security Property ssl.spiffe.accept.
     *                If the sslProcotol is not provided, the default TLSv1.2 is used.
     *
     * @return a Result containing a SSLContext
     */
    public static Result<SSLContext, String> getSslContext(@NonNull SslContextOptions options) {
        try {
            SSLContext sslContext;
            if (StringUtils.isNotBlank(options.sslProtocol)) {
                sslContext = SSLContext.getInstance(options.sslProtocol);
            } else {
                sslContext = SSLContext.getInstance(DEFAULT_SSL_PROTOCOL);
            }

            if (options.x509Source == null) {
                return Result.error("x509Source option cannot be null, a X509 Source must be provided");
            }

            sslContext.init(
                    new SpiffeKeyManagerFactory().engineGetKeyManagers(options.x509Source),
                    new SpiffeTrustManagerFactory().engineGetTrustManagers(options.x509Source, options.acceptedSpiffeIdsSupplier),
                    null);

            return Result.ok(sslContext);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            return Result.error("Error creating SSL Context: %s %n %s", e.getMessage(), ExceptionUtils.getStackTrace(e));
        }
    }

    /**
     * Options for creating a new SslContext.
     */
    @Data
    public static class SslContextOptions {
        String sslProtocol;
        X509Source x509Source;
        Supplier<Result<List<SpiffeId>, String>> acceptedSpiffeIdsSupplier;

        @Builder
        public SslContextOptions(
                String sslProtocol,
                X509Source x509Source,
                Supplier<Result<List<SpiffeId>, String>> acceptedSpiffeIdsSupplier) {
            this.x509Source = x509Source;
            this.acceptedSpiffeIdsSupplier = acceptedSpiffeIdsSupplier;
            this.sslProtocol = sslProtocol;
        }
    }
}
