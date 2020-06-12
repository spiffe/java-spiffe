package spiffe.provider;

import spiffe.exception.SocketEndpointAddressException;
import spiffe.exception.X509SourceException;
import spiffe.workloadapi.X509Source;

/**
 * A <code>X509SourceManager</code> is a Singleton that handles an instance of a X509Source.
 * <p>
 * The default SPIFFE socket enpoint address is used to create a X509Source backed by the
 * Workload API.
 * If the environment variable is not defined, it will throw an <code>IllegalStateException</code>.
 * If the X509Source cannot be initialized, it will throw a <code>RuntimeException</code>.
 * <p>
 *
 * @implNote This Singleton needed to be able to handle a single {@link X509Source} instance
 * to be used by the {@link SpiffeKeyManagerFactory} and {@link SpiffeTrustManagerFactory} to inject it
 * in the {@link SpiffeKeyManager} and {@link SpiffeTrustManager} instances.
 */
public class X509SourceManager {

    private static X509Source x509Source;

    private X509SourceManager() {
    }

    /**
     * Returns the single instance handled by this singleton. If the instance has not been
     * created yet, it creates a new X509Source and initializes the singleton in a thread safe way.
     *
     * @return a {@link X509Source}
     * @throws X509SourceException            if the X.509 source could not be initialized
     * @throws SocketEndpointAddressException is the socket endpoint address is not valid
     */
    public static synchronized X509Source getX509Source() throws X509SourceException, SocketEndpointAddressException {
        if (x509Source == null) {
            x509Source = X509Source.newSource();
        }
        return x509Source;
    }
}
