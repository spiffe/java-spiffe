package io.spiffe.provider;

import io.spiffe.svid.x509svid.X509SvidSource;
import lombok.NonNull;
import lombok.val;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;

import static io.spiffe.provider.SpiffeProviderConstants.DEFAULT_ALIAS;

/**
 * Represents an X.509 key manager for the SPIFFE provider.
 * <p>
 * Provides the chain of X.509 certificates and the private key to be used in secure socket negotiations.
 */
public final class SpiffeKeyManager extends X509ExtendedKeyManager {

    private final X509SvidSource x509SvidSource;

    /**
     * Constructor.
     *
     * @param x509SvidSource source of X.509 SVIDs
     */
    public SpiffeKeyManager(@NonNull final X509SvidSource x509SvidSource) {
        this.x509SvidSource = x509SvidSource;
    }

    /**
     * Returns the X.509 certificates chain associated with the given alias.
     *
     * @return the certificate chain (ordered with the leaf certificate first and the intermediate CA certificates),
     * or an empty Array if the alias is not 'Spiffe'.
     */
    @Override
    public X509Certificate[] getCertificateChain(final String alias) {
        if (!Objects.equals(alias, DEFAULT_ALIAS)) {
            return new X509Certificate[0];
        }
        val x509Svid = x509SvidSource.getX509Svid();
        return x509Svid.getChainArray();
    }

    /**
     * Returns the private key handled by this key manager.
     *
     * @param alias a key entry, as this KeyManager only handles one identity, i.e. one SVID,
     *              it will return the PrivateKey if the given alias is 'Spiffe'.
     * @return the {@link PrivateKey} handled by this key manager, or null if the alias is not 'Spiffe'
     */
    @Override
    public PrivateKey getPrivateKey(final String alias) {
        // if the alias specified is not the alias handled by the current KeyManager, return null
        if (!Objects.equals(alias, DEFAULT_ALIAS)) {
            return null;
        }

        val x509Svid = x509SvidSource.getX509Svid();
        return x509Svid.getPrivateKey();
    }


    @Override
    public String[] getClientAliases(final String keyType, final Principal[] issuers) {
        return getAliases(keyType);
    }

    @Override
    public String chooseClientAlias(final String[] keyTypes, final Principal[] issuers, final Socket socket) {
        return getAlias(keyTypes);
    }

    @Override
    public String chooseEngineClientAlias(final String[] keyTypes, final Principal[] issuers, final SSLEngine sslEngine) {
        return getAlias(keyTypes);
    }

    @Override
    public String[] getServerAliases(final String keyType, final Principal[] issuers) {
        return getAliases(keyType);
    }

    @Override
    public String chooseEngineServerAlias(final String keyType, final Principal[] issuers, final SSLEngine sslEngine) {
        return getAlias(keyType);
    }

    @Override
    public String chooseServerAlias(final String keyType, final Principal[] issuers, final Socket socket) {
        return getAlias(keyType);
    }

    // If the algorithm of the PrivateKey is supported (is in the list of keyTypes), then returns
    // the ALIAS handled by the current KeyManager, if it's not supported returns null
    private String getAlias(final String... keyTypes) {
        val x509Svid = x509SvidSource.getX509Svid();

        val privateKeyAlgorithm = x509Svid.getPrivateKey().getAlgorithm();
        if (Arrays.asList(keyTypes).contains(privateKeyAlgorithm)) {
            return DEFAULT_ALIAS;
        }
        return null;
    }

    private String[] getAliases(final String keyType) {
        val alias = getAlias(keyType);
        return new String[]{alias};
    }
}
