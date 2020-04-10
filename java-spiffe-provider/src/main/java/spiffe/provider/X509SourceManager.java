package spiffe.provider;

import lombok.val;
import org.apache.commons.lang3.StringUtils;
import spiffe.SpiffeConstants;
import spiffe.workloadapi.X509Source;

import java.nio.file.Paths;

/**
 * A <code>X509SourceManager</code> is a Singleton that handles an instance of a X509Source.
 * Uses the environment variable 'SPIFFE_ENDPOINT_SOCKET' to create a X509Source backed by the
 * Workload API.
 * If the environment variable is not defined, it will throw an <code>IllegalStateException</code>.
 * If the X509Source cannot be initialized, it will throw a <code>RuntimeException</code>.
 * <p>
 * @implNote The reason to have this Singleton is because we need to have
 * a single X509Source instance to be used by the {@link SpiffeKeyManagerFactory}
 * and {@link SpiffeTrustManagerFactory} to inject it in the {@link SpiffeKeyManager} and {@link SpiffeTrustManager}
 * instances.
 */
public enum X509SourceManager {

    INSTANCE;

    private final X509Source x509Source;

    X509SourceManager() {
        val spiffeSocketEnvVariable = System.getenv(SpiffeConstants.SOCKET_ENV_VARIABLE);
        if (StringUtils.isBlank(spiffeSocketEnvVariable)) {
            throw new IllegalStateException("SPIFFE SOCKET ENV VARIABLE IS NOT SET");
        }

        val x509SourceResult =
                X509Source.newSource(Paths.get(spiffeSocketEnvVariable));
        if (x509SourceResult.isError()) {
            // panic in case of error creating the X509Source
            throw new RuntimeException(x509SourceResult.getError());
        }

        // set the singleton instance
        x509Source = x509SourceResult.getValue();
    }

    public X509Source getX509Source() {
        return x509Source;
    }
}
