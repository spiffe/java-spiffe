package spiffe.provider;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static spiffe.provider.CertificateUtils.checkSpiffeId;
import static spiffe.provider.CertificateUtils.validate;

/**
 * This class implements a SPIFFE based TrustManager
 *
 */
public class SpiffeTrustManager extends X509ExtendedTrustManager {

    private final SpiffeIdManager spiffeIdManager;

    SpiffeTrustManager() {
        spiffeIdManager = SpiffeIdManager.getInstance();
    }

    /**
     * Given the partial or complete certificate chain provided by the peer,
     * build a certificate path to a trusted root and return if it can be validated
     * and is trusted for client SSL authentication based on the authentication type.
     *
     * @param chain the peer certificate chain
     * @param authType the authentication type based on the client certificate
     * @throws CertificateException
     */
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkPeer(chain);
    }

    /**
     * Given the partial or complete certificate chain provided by the peer,
     * build a certificate path to a trusted root and return if it can be validated
     * and is trusted for server SSL authentication based on the authentication type.
     *
     * @param chain the peer certificate chain
     * @param authType the key exchange algorithm used
     * @throws CertificateException
     */
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkPeer(chain);
    }

    /**
     * Return an array of certificate authority certificates which are trusted for authenticating peers.
     *
     * @return a non-null (possibly empty) array of acceptable CA issuer certificates
     */
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return spiffeIdManager.getTrustedCerts().toArray(new X509Certificate[0]);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        checkServerTrusted(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        checkServerTrusted(chain, authType);
    }

    /**
     * Validates the peer's SVID
     *
     * @param chain an array of X509Certificate that contains the Peer's SVID to be validated
     * @throws CertificateException when either the Peer's certificate doesn't chain to any Trusted CA
     *
     */
    private void checkPeer(X509Certificate[] chain) throws CertificateException {
        validate(chain, spiffeIdManager.getTrustedCerts());
        checkSpiffeId(chain);
    }
}
