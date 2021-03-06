package io.spiffe.provider;

import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.exception.X509SourceException;
import io.spiffe.workloadapi.DefaultX509Source;
import io.spiffe.workloadapi.X509Source;

/**
 * Singleton that handles an instance of a {@link DefaultX509Source} that implements an {@link X509Source}.
 * <p>
 * The default SPIFFE socket endpoint address is used to create an X.509 Source backed by the
 * Workload API.
 * <p>
 * If the environment variable is not defined, it will throw an <code>IllegalStateException</code>.
 * If the X509Source cannot be initialized, it will throw a <code>RuntimeException</code>.
 * <p>
 * This Singleton needed to be able to handle a single {@link DefaultX509Source} instance
 * to be used by the {@link SpiffeKeyManagerFactory} and {@link SpiffeTrustManagerFactory} to inject it
 * in the {@link SpiffeKeyManager} and {@link SpiffeTrustManager} instances.
 */
public final class X509SourceManager {

    private static X509Source x509Source;

    private X509SourceManager() {
    }

    /**
     * Returns the single instance handled by this singleton. If the instance has not been
     * created yet, it creates a new X509Source and initializes the singleton in a thread safe way.
     *
     * @return the single instance of {@link DefaultX509Source}
     * @throws X509SourceException            if the X.509 source could not be initialized
     * @throws SocketEndpointAddressException is the socket endpoint address is not valid
     */
    public static synchronized X509Source getX509Source() throws X509SourceException, SocketEndpointAddressException {
        if (x509Source == null) {
            x509Source = DefaultX509Source.newSource();
        }
        return x509Source;
    }
}
