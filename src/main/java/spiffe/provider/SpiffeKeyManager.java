package spiffe.provider;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import static spiffe.provider.SpiffeProviderConstants.ALIAS;

/**
 *
 * Implementation of the KeyManager for the Spiffe Provider
 *
 * Provides the Certificate Chain and the Private Key of the SVID
 *
 */
public class SpiffeKeyManager extends X509ExtendedKeyManager {

    private SpiffeIdManager spiffeIdManager;

    SpiffeKeyManager() {
        spiffeIdManager = SpiffeIdManager.getInstance();
    }

    /**
     * The Certificate Chain that the workload presents to the other peer.
     *
     * @return the X.509 SVID Certificates
     */
    @Override
    public X509Certificate[] getCertificateChain(String s) {
        return spiffeIdManager.getCertificateChain().toArray(new X509Certificate[0]);
    }

    /**
     * Returns the Private Key associated to the SVID certificate
     *
     * @return the Private Key
     */
    @Override
    public PrivateKey getPrivateKey(String alias) {
        if (!Objects.equals(alias, ALIAS)) {
            return null;
        }
        return spiffeIdManager.getPrivateKey();
    }


    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return getAliases(keyType);
    }

    @Override
    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        return getAlias(keyTypes);
    }

    @Override
    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine sslEngine) {
        return getAlias(keyTypes);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return getAliases(keyType);
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine sslEngine) {
        return getAlias(keyType);
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return getAlias(keyType);
    }

    /**
     * If the algorithm is supported returns the ALIAS of the Provider, if it's not supported returns null
     *
     * @param keyTypes
     * @return
     */
    private String getAlias(String...keyTypes) {
        String privateKeyAlgorithm = spiffeIdManager.getPrivateKey().getAlgorithm();
        if (Arrays.asList(keyTypes).contains(privateKeyAlgorithm)) {
            return ALIAS;
        }
        return null;
    }

    private String[] getAliases(String keyType) {
        String alias = getAlias(keyType);
        return new String[]{alias};
    }
}
