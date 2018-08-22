package spiffe.provider;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import java.security.KeyStore;

public class SpiffeKeyManagerFactory extends KeyManagerFactorySpi {

    @Override
    protected void engineInit(KeyStore keyStore, char[] chars) {

    }

    @Override
    protected void engineInit(ManagerFactoryParameters managerFactoryParameters) {

    }

    @Override
    protected KeyManager[] engineGetKeyManagers() {
        return new KeyManager[] {new SpiffeKeyManager()};
    }
}
