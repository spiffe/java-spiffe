package spiffe.provider;

import lombok.val;
import spiffe.svid.x509svid.X509SvidSource;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

import static spiffe.provider.SpiffeProviderConstants.DEFAULT_ALIAS;

/**
 * A <code>SpiffeKeyManager</code> represents a X509 KeyManager for the SPIFFE Provider.
 * <p>
 * Provides the chain of X509 Certificates and the Private Key.
 */
public final class SpiffeKeyManager extends X509ExtendedKeyManager {

    private final X509SvidSource x509SvidSource;

    public SpiffeKeyManager(X509SvidSource x509SvidSource) {
        this.x509SvidSource = x509SvidSource;
    }

    /**
     * Returns the certificate chain associated with the given alias.
     *
     * @return the X.509 SVID Certificates
     */
    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        if (!Objects.equals(alias, DEFAULT_ALIAS)) {
            return null;
        }
        return x509SvidSource.getX509Svid().getChainArray();
    }

    /**
     * Returns the key associated with the given alias.
     *
     * @param alias a key entry, as this KeyManager only handles one identity, i.e. one SVID,
     * it will return the PrivateKey if the alias asked for is 'Spiffe'.
     *
     * @return the Private Key
     */
    @Override
    public PrivateKey getPrivateKey(String alias) {
        // if the alias specified is not the alias handled by the current KeyManager, return null
        if (!Objects.equals(alias, DEFAULT_ALIAS)) {
            return null;
        }

        return x509SvidSource
                .getX509Svid()
                .getPrivateKey();
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

    // If the algorithm of the PrivateKey is supported (is in the list of keyTypes), then returns
    // the ALIAS handled by the current KeyManager, if it's not supported returns null
    private String getAlias(String... keyTypes) {
        val x509Svid = Optional.ofNullable(x509SvidSource.getX509Svid());
        if (!x509Svid.isPresent()) {
            return null;
        }

        val privateKeyAlgorithm = x509Svid.get().getPrivateKey().getAlgorithm();
        if (Arrays.asList(keyTypes).contains(privateKeyAlgorithm)) {
            return DEFAULT_ALIAS;
        }
        return null;
    }

    private String[] getAliases(String keyType) {
        val alias = getAlias(keyType);
        return new String[]{alias};
    }
}
