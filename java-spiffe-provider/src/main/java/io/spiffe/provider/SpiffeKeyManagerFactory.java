package io.spiffe.provider;

import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.exception.X509SourceException;
import io.spiffe.workloadapi.X509Source;
import lombok.NonNull;
import lombok.val;
import io.spiffe.svid.x509svid.X509SvidSource;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import java.security.KeyStore;

/**
 * Implementation of a {@link KeyManagerFactorySpi} to create a {@link KeyManager} that is backed by the Workload API.
 * <p>
 * The Java Security API will call <code>engineGetKeyManagers()</code> to get an instance of a KeyManager. This KeyManager
 * instance is injected with a {@link X509Source} to obtain the latest X.509 SVIDs updates from the
 * Workload API.
 *
 * @see SpiffeSslContextFactory
 * @see X509SvidSource
 * @see X509SourceManager
 * @see SpiffeSslContextFactory
 */
public final class SpiffeKeyManagerFactory extends KeyManagerFactorySpi {

    /**
     * Default method for creating the KeyManager, uses a {@link X509Source} instance
     * that is handled by the Singleton {@link X509SourceManager}
     *
     * @throws SpiffeProviderException in case there is an error setting up the X.509 source
     */
    @Override
    protected KeyManager[] engineGetKeyManagers() {
        SpiffeKeyManager spiffeKeyManager;
        X509Source x509Source;
        try {
            x509Source = X509SourceManager.getX509Source();
        } catch (X509SourceException e) {
            throw new SpiffeProviderException("The X.509 source could not be created", e);
        } catch (SocketEndpointAddressException e) {
            throw new SpiffeProviderException("The Workload API Socket endpoint address configured is not valid", e);
        }

        spiffeKeyManager = new SpiffeKeyManager(x509Source);
        return new KeyManager[]{spiffeKeyManager};
    }

    /**
     * This method creates a new key manager and initializes it with the given X.509 SVID source.
     *
     * @param x509SvidSource an instance of a {@link X509SvidSource}
     * @return an array with an instance of a {@link KeyManager}
     */
    public KeyManager[] engineGetKeyManagers(@NonNull X509SvidSource x509SvidSource) {
        val spiffeKeyManager = new SpiffeKeyManager(x509SvidSource);
        return new KeyManager[]{spiffeKeyManager};
    }

    @Override
    protected void engineInit(KeyStore keyStore, char[] chars) {
        //no implementation needed
    }

    @Override
    protected void engineInit(ManagerFactoryParameters managerFactoryParameters) {
        //no implementation needed
    }

}
