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
 * @implNote This Singleton needed to be able to handle a single {@link X509Source} instance
 * to be used by the {@link SpiffeKeyManagerFactory} and {@link SpiffeTrustManagerFactory} to inject it
 * in the {@link SpiffeKeyManager} and {@link SpiffeTrustManager} instances.
 */
public enum X509SourceManager {

    INSTANCE;

    private final X509Source x509Source;

    X509SourceManager() {
        try {
            x509Source = X509Source.newSource();
        } catch (SocketEndpointAddressException e) {
            throw new X509SourceException("Could not create X509 Source. Socket endpoint address is not valid", e);
        }
    }

    public X509Source getX509Source() {
        return x509Source;
    }
}
